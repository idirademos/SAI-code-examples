#!/usr/bin/env python3
"""OAuth 2.1 + MCP client for CyberArk AI Gateway (Identity bridge).

This script uses OAuth 2.1 with PKCE only (no client secret): authorization code
flow with code_challenge/code_verifier. It then connects to an MCP (Model Context
Protocol) endpoint to list tools and optionally call one. Configuration is via
environment variables (see .env.example).

Environment variables:
    TENANT_URL       Gateway base URL (e.g. https://aigw.example.cloud).
    CLIENT_ID        OAuth client ID.
    CLIENT_SECRET    OAuth client secret (used with PKCE on token request).
    REDIRECT_URI      Callback URL (must be registered in CyberArk Identity).
    MCP_PATH         MCP path (default: /mcp/deep-wiki).
    SCOPE            OAuth scope (default: full).
    SKIP_OAUTH       If "true", use ACCESS_TOKEN from env and skip OAuth.
    ACCESS_TOKEN     Used when SKIP_OAUTH=true.
    TOOL_NAME        Optional MCP tool to call.
    TOOL_ARGS_JSON   Optional JSON object of arguments for the tool.
    LIST_TOOLS       If "false", skip listing tools when TOOL_NAME is set (default: true, always list).

Usage:
    Copy .env.example to .env, set the variables, then:
    python mcp_oauth_client.py
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import requests
from dotenv import load_dotenv
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from tabulate import tabulate

# Callback wait timeout (seconds). The MCP path comes from the MCP_PATH env var.
CALLBACK_TIMEOUT = 300


def _verify_tls() -> bool:
    """Whether to verify TLS certs. Set INSECURE_SKIP_VERIFY=true to disable.

    WARNING: disabling verification is for dev/integration environments with
    self-signed certs only. Never use it with production credentials.
    """
    skip = os.getenv("INSECURE_SKIP_VERIFY", "").lower() == "true"
    if skip:
        # Silence the per-request InsecureRequestWarning from urllib3.
        from urllib3.exceptions import InsecureRequestWarning

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]
    return not skip


def _mcp_http_client_factory(
    headers: Dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """MCP httpx client factory that honors INSECURE_SKIP_VERIFY.

    Mirrors mcp.shared._httpx_utils.create_mcp_http_client defaults, adding
    verify=False when TLS verification is disabled.
    """
    from mcp.shared._httpx_utils import (
        MCP_DEFAULT_SSE_READ_TIMEOUT,
        MCP_DEFAULT_TIMEOUT,
    )

    kwargs: Dict[str, Any] = {"follow_redirects": True, "verify": _verify_tls()}
    if timeout is None:
        kwargs["timeout"] = httpx.Timeout(MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT)
    else:
        kwargs["timeout"] = timeout
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


def _step(msg: str) -> None:
    """Print a step label to stdout."""
    print(f"\n==> {msg}")


def _to_jsonable(obj: Any) -> Any:
    """Convert MCP/Pydantic objects to JSON-serializable form."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    if isinstance(obj, (dict, list, str, int, float, bool)) or obj is None:
        return obj
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


def _normalize_tool_result(result: Any) -> dict[str, Any]:
    """Turn MCP call_tool result into a JSON-serializable dict for display.

    Extracts isError, structuredContent, and content (text from each item).
    Used so tool output prints as readable JSON instead of raw object repr.

    Args:
        result: Return value from session.call_tool() (may have content, structuredContent, isError).

    Returns:
        Dict with isError, structuredContent, and/or content as appropriate.
    """
    out: dict[str, Any] = {}
    if hasattr(result, "isError") and result.isError is not None:
        out["isError"] = result.isError
    if hasattr(result, "structuredContent") and result.structuredContent is not None:
        out["structuredContent"] = _to_jsonable(result.structuredContent)
    if hasattr(result, "content") and result.content:
        parts = []
        for item in result.content:
            if hasattr(item, "text"):
                parts.append(item.text)
            else:
                parts.append(_to_jsonable(item))
        out["content"] = parts[0] if len(parts) == 1 else parts
    if not out:
        return _to_jsonable(result) if isinstance(_to_jsonable(result), dict) else {"result": _to_jsonable(result)}
    return out


def _format_duration(seconds: float) -> str:
    """Format a duration in seconds for display (e.g. 1.23s or 456 ms)."""
    if seconds >= 1.0:
        return f"{seconds:.2f}s"
    return f"{seconds * 1000:.0f} ms"


def _decode_jwt_segment(segment: str) -> dict[str, Any]:
    """Base64url-decode a single JWT segment (header or payload) into a dict."""
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode()))


def _print_token_details(access_token: str) -> None:
    """Print the full access token and, if it is a JWT, its decoded claims.

    Helps diagnose why a token is rejected: check aud (audience/resource),
    scope, iss (issuer), and exp (expiry) against what the MCP resource expects.
    """
    print(f"Access token (full):\n{access_token}\n")
    parts = access_token.split(".")
    if len(parts) != 3:
        print("Token is not a JWT (opaque token) — cannot decode claims locally.")
        return
    try:
        header = _decode_jwt_segment(parts[0])
        payload = _decode_jwt_segment(parts[1])
    except Exception as exc:  # noqa: BLE001
        print(f"Could not decode JWT: {exc}")
        return
    print("JWT header:")
    print(json.dumps(header, indent=2, sort_keys=True))
    print("JWT claims:")
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))

    # Show the claims most relevant to whether the resource will accept the token.
    rows: list[tuple[str, str]] = []
    for claim in ("iss", "aud", "scope", "scp", "sub", "client_id", "azp", "agent_name"):
        if claim in payload:
            rows.append((claim, str(payload[claim])))

    # Verdict: locally we can only check structure + expiry (signature needs the
    # issuer's JWKS). Report expiry explicitly and note the limits of a local check.
    exp = payload.get("exp")
    expired = False
    if isinstance(exp, (int, float)):
        remaining = exp - time.time()
        expired = remaining < 0
        rows.append(("exp", f"{'EXPIRED ' + format(abs(remaining), '.0f') + 's ago' if expired else 'valid for ' + format(remaining, '.0f') + 's'}"))
    else:
        rows.append(("exp", "not present"))

    if expired:
        verdict = "INVALID — token has expired; run the OAuth flow again."
    else:
        verdict = "VALID (structurally): well-formed JWT, not expired. NOTE: signature/audience not verified locally — only the gateway can fully validate."
    rows.append(("Token verdict", verdict))
    print("\n" + tabulate(rows, headers=["Claim", "Value"], tablefmt="grid"))


def _unwrap_exception(exc: BaseException) -> BaseException:
    """Recursively get the leaf exception from ExceptionGroups (e.g. from anyio TaskGroup)."""
    while getattr(exc, "exceptions", None) and len(exc.exceptions) > 0:
        exc = exc.exceptions[0]
    return exc


def _print_mcp_error(detail: BaseException, mcp_url: str) -> None:
    """Print a clear, user-friendly MCP error summary with suggested actions."""
    msg = str(detail).strip()
    rows = [("Error", msg)]

    # Surface the HTTP response body — gateways put policy-denial reasons there.
    response = getattr(detail, "response", None)
    body = ""
    if response is not None:
        try:
            body = (response.text or "").strip()
        except Exception:
            body = ""
    if body:
        rows.append(("Response body", body[:2000]))

    if "503" in msg or "Service Unavailable" in msg:
        rows += [("Why", "The gateway rejected the request before reaching the upstream MCP service. "
                          "On an AI gateway this is often a policy denial (route/tool not enabled, "
                          "entitlement or quota) rather than the backend being down."),
                 ("Try", "Read the response body above for the reason. Confirm with the gateway admin "
                         "that MCP_PATH is enabled for this client and that no guardrail/quota is blocking it.")]
    elif "504" in msg or "Gateway Time-out" in msg or "timeout" in msg.lower():
        rows += [("Why", "The gateway or upstream server did not respond in time."),
                 ("Try", "Run again, use a simpler tool, or ask the gateway admin to increase timeouts.")]
    elif "invalid params" in msg or "missing properties" in msg:
        rows += [("Why", "The tool requires arguments that were not provided."),
                 ("Try", "Set TOOL_ARGS_JSON in .env with the required keys (see .env.example).")]
    elif "401" in msg or "Unauthorized" in msg:
        rows += [("Why", "The access token was rejected or expired."),
                 ("Try", "Run the OAuth flow again (do not use SKIP_OAUTH) to get a new token.")]
    else:
        rows.append(("Try", "Check the gateway is reachable and your token is valid."))
    print("\n" + tabulate(rows, tablefmt="grid") + "\n")


def probe_mcp_raw(mcp_url: str, access_token: str) -> None:
    """Send a raw authenticated MCP 'initialize' POST and print the gateway's reply.

    The MCP client library raises on non-2xx and discards the httpx response, so
    policy/routing details in the body are lost. This bypasses it to show the
    exact status, headers, and body the gateway returns.
    """
    _step("Raw gateway response probe")
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcp-oauth-client-probe", "version": "1.0"},
        },
    }
    try:
        resp = httpx.post(
            mcp_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Mcp-Protocol-Version": "2025-06-18",
            },
            json=payload,
            timeout=30,
            verify=_verify_tls(),
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Raw probe request failed: {type(exc).__name__}: {exc}")
        return
    body_text = (resp.text or "").strip()
    content_type = resp.headers.get("content-type", "")
    if "html" in content_type.lower():
        # Gateway returned an HTML error page — extract title + visible text,
        # dropping <style>/<script> and tags so the actual message shows.
        cleaned = re.sub(r"(?is)<(script|style).*?</\1>", " ", body_text)
        title_match = re.search(r"(?is)<title>(.*?)</title>", cleaned)
        visible = re.sub(r"(?s)<[^>]+>", " ", cleaned)
        visible = re.sub(r"\s+", " ", visible).strip()
        display_body = ""
        if title_match:
            display_body = f"[title] {title_match.group(1).strip()}\n"
        display_body += visible[:1000]
    else:
        display_body = body_text[:2000] or "(empty)"
    rows = [
        ("HTTP status", f"{resp.status_code} {resp.reason_phrase}"),
        ("Content-Type", content_type or "(none)"),
        ("Response body", display_body or "(empty)"),
    ]
    interesting = ("www-authenticate", "content-type", "x-request-id", "x-amzn-requestid", "x-envoy-upstream-service-time", "server")
    for key in interesting:
        if key in resp.headers:
            rows.append((f"header: {key}", resp.headers[key]))
    print(tabulate(rows, tablefmt="grid"))


def _flatten_key_value(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Flatten a dict-like object into (key, value) pairs for table display.

    Nested dicts produce dotted keys (e.g. serverInfo.name). None and empty
    dict/list are shown as "—". Used by the init/server info table.

    Args:
        obj: A dict-like or JSON-serializable value (e.g. MCP init result).
        prefix: Optional key prefix for nested recursion.

    Returns:
        List of (key, value) tuples, with value as string.
    """
    out: list[tuple[str, str]] = []
    data = _to_jsonable(obj)
    if not isinstance(data, dict):
        out.append((prefix or "value", str(data)))
        return out
    for k, v in sorted(data.items()):
        key = f"{prefix}.{k}" if prefix else k
        if v is None:
            out.append((key, "—"))
        elif isinstance(v, bool):
            out.append((key, str(v).lower()))
        elif isinstance(v, (str, int, float)):
            out.append((key, str(v)))
        elif isinstance(v, dict):
            if not v:
                out.append((key, "—"))
            else:
                out.extend(_flatten_key_value(v, key))
        elif isinstance(v, list):
            out.append((key, json.dumps(v, default=str) if v else "—"))
        else:
            out.append((key, str(v)))
    return out


def _print_init_table(label: str, obj: Any) -> None:
    """Print MCP init response or server info as a Key | Value table (tabulate grid)."""
    rows = _flatten_key_value(obj)
    print(label)
    if not rows:
        print("(empty)")
        return
    key_w, val_w = 48, 64
    truncated = [(k[:key_w], (v or "—")[:val_w]) for k, v in rows]
    print(tabulate(truncated, headers=["Key", "Value"], tablefmt="grid"))


def _tool_annotations_row(t: Any) -> tuple[str, str]:
    """Extract (name, annotations summary) for one tool for display."""
    name = getattr(t, "name", None) or ""
    ann = getattr(t, "annotations", None)
    if ann is None:
        return name, "—"
    parts = []
    for key in ("title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        val = getattr(ann, key, None)
        if val is not None:
            parts.append(f"{key}={val}")
    return name, " ".join(parts) if parts else "—"


def _print_tools_table(tool_list: list) -> None:
    """Print MCP tools as Name | Description table, then MCP annotations per tool (tabulate grid)."""
    print("Available tools:")
    if not tool_list:
        print("(none)")
        return
    desc_w = 72
    rows = []
    for t in tool_list:
        name = getattr(t, "name", None) or ""
        desc = (getattr(t, "description", None) or "").replace("\n", " ").strip()
        if len(desc) > desc_w:
            desc = desc[: desc_w - 3] + "..."
        rows.append((name, desc))
    print(tabulate(rows, headers=["Name", "Description"], tablefmt="grid"))

    # MCP annotations (ToolAnnotations: title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
    ann_rows = [_tool_annotations_row(t) for t in tool_list]
    if any(cell != "—" for _, cell in ann_rows):
        print("\nMCP annotations (per tool):")
        print(tabulate(ann_rows, headers=["Tool", "Annotations"], tablefmt="grid"))

    # inputSchema summary (required / properties) when present
    schema_rows: list[tuple[str, str]] = []
    for t in tool_list:
        name = getattr(t, "name", None) or ""
        schema = getattr(t, "inputSchema", None) or {}
        if isinstance(schema, dict) and schema:
            req = schema.get("required", [])
            props = schema.get("properties", {})
            req_s = ", ".join(req) if req else "—"
            prop_names = ", ".join(props.keys())[:80] if props else "—"
            schema_rows.append((name, f"required: [{req_s}]  properties: {prop_names}"))
    if schema_rows:
        print("\nInput schema (per tool):")
        print(tabulate(schema_rows, headers=["Tool", "Schema"], tablefmt="grid"))


def generate_pkce_pair() -> Tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256) per RFC 7636.

    Returns:
        (code_verifier, code_challenge) for OAuth 2.1 authorization code flow.
    """
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def normalize_base_url(tenant_url: str) -> str:
    """Normalize the tenant URL for use in OAuth and MCP requests.

    Ensures a scheme (https if missing), strips whitespace, and removes
    a trailing slash. Raises if the value is empty.

    Args:
        tenant_url: Raw TENANT_URL from env (e.g. host only or full URL).

    Returns:
        Base URL with scheme and no trailing slash (e.g. https://host.example.com).

    Raises:
        ValueError: If tenant_url is empty or whitespace-only.
    """
    if not tenant_url or not tenant_url.strip():
        raise ValueError("TENANT_URL is required")
    base = tenant_url.strip()
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    return base.rstrip("/")


def build_authorize_url(
    base_url: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: str,
    state: str,
) -> str:
    """Build the OAuth 2.1 authorization URL (authorization code + PKCE).

    The resulting URL is opened in the browser; after login, the user is
    redirected to redirect_uri with a ?code=...&state=... query.

    Args:
        base_url: Gateway base URL (no trailing slash).
        client_id: OAuth client identifier.
        redirect_uri: Callback URL registered in CyberArk Identity.
        scope: Scope string (e.g. "full").
        code_challenge: PKCE code challenge (S256).
        state: CSRF state value.

    Returns:
        Full URL to the /OAuth2/Authorize endpoint with query parameters.
    """
    params: Dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{base_url}/OAuth2/Authorize?{urlencode(params)}"


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the 'code' query param from the OAuth redirect."""

    def __init__(self, *args, callback_data: Dict[str, str], **kwargs):
        self.callback_data = callback_data
        super().__init__(*args, **kwargs)

    def do_GET(self):  # noqa: N802
        params = parse_qs(urlparse(self.path).query)
        if "code" in params:
            self.callback_data["code"] = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"Authorization complete. You can close this window.")
        else:
            self.send_response(400)
            self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


class CallbackServer:
    """Runs a local HTTP server on REDIRECT_URI host:port to receive the OAuth code."""

    def __init__(self, redirect_uri: str):
        parsed = urlparse(redirect_uri)
        self.host = parsed.hostname or "localhost"
        self.port = parsed.port or 80
        self._data: Dict[str, str] = {"code": ""}
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the server in a background thread."""
        def handler(*args, **kwargs):
            CallbackHandler(*args, callback_data=self._data, **kwargs)
        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the server and wait for the thread to finish."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=1)

    def wait_for_code(self, timeout_seconds: int = CALLBACK_TIMEOUT) -> str:
        """Block until the redirect delivers a code or timeout."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if self._data["code"]:
                return self._data["code"]
            time.sleep(0.1)
        raise TimeoutError("Timed out waiting for authorization code")


def exchange_code_for_token(
    base_url: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> Dict[str, str]:
    """Exchange the authorization code for an access token (OAuth 2.1 PKCE + client credentials).

    POSTs to the gateway token endpoint with grant_type=authorization_code,
    code_verifier (PKCE), and client_secret. PKCE and client credentials do not conflict.

    Args:
        base_url: Gateway base URL (no trailing slash).
        client_id: OAuth client identifier.
        client_secret: OAuth client secret.
        code: Authorization code from the redirect callback.
        redirect_uri: Same redirect_uri used in the authorize request.
        code_verifier: PKCE code verifier that matches the code_challenge sent at authorize.

    Returns:
        Token response JSON (e.g. access_token, expires_in, refresh_token).

    Raises:
        requests.HTTPError: On non-2xx response from the token endpoint.
    """
    response = requests.post(
        f"{base_url}/OAuth2/Token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "scope": "full",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
        verify=_verify_tls(),
    )
    response.raise_for_status()
    return response.json()


async def connect_mcp(base_url: str, mcp_path: str, access_token: str) -> None:
    """Connect to the MCP endpoint, initialize, list tools, and optionally call a tool.

    Uses TOOL_NAME and TOOL_ARGS_JSON from the environment when invoking a tool.
    Prints server info and tools as tables; prints tool result as JSON.
    On failure, prints a user-friendly error summary and re-raises.

    Args:
        base_url: Gateway base URL (no trailing slash).
        mcp_path: MCP path (e.g. /mcp or /mcp/deep-wiki).
        access_token: Bearer token from OAuth2 token endpoint.
    """
    mcp_url = f"{base_url}{mcp_path}"
    headers = {"Authorization": f"Bearer {access_token}"}
    tool_name = os.getenv("TOOL_NAME", "").strip()
    tool_args_raw = os.getenv("TOOL_ARGS_JSON", "").strip()
    tool_args: Dict[str, Any] = {}
    if tool_args_raw:
        try:
            tool_args = json.loads(tool_args_raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid TOOL_ARGS_JSON: {exc}") from exc

    try:
        timings: list[tuple[str, str]] = []
        async with streamablehttp_client(
            url=mcp_url, headers=headers, httpx_client_factory=_mcp_http_client_factory
        ) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                _step("Connecting to MCP")
                t0 = time.perf_counter()
                init_result = await session.initialize()
                timings.append(("initialize()", _format_duration(time.perf_counter() - t0)))
                _step("MCP server info")
                server_info = getattr(init_result, "server_info", None)
                _print_init_table("Server:" if server_info is not None else "Init response:", server_info or init_result)

                # List tools by default; set LIST_TOOLS=false to skip when calling a single tool
                list_tools = os.getenv("LIST_TOOLS", "true").lower() != "false"
                if list_tools:
                    _step("List tools")
                    t0 = time.perf_counter()
                    tools_result = await session.list_tools()
                    timings.append(("list_tools()", _format_duration(time.perf_counter() - t0)))
                    _print_tools_table(getattr(tools_result, "tools", []) or [])

                if tool_name:
                    _step(f"Calling tool: {tool_name}")
                    t0 = time.perf_counter()
                    result = await session.call_tool(tool_name, tool_args)
                    timings.append((f"call_tool({tool_name!r})", _format_duration(time.perf_counter() - t0)))
                    print(f"Tool result ({tool_name}):")
                    print(json.dumps(_normalize_tool_result(result), indent=2, sort_keys=True, default=str))

                if timings:
                    _step("Timings")
                    print(tabulate(timings, headers=["Step", "Duration"], tablefmt="grid"))
    except Exception as exc:
        detail = _unwrap_exception(exc)
        _print_mcp_error(detail, mcp_url)
        # The MCP client hides the HTTP response; re-issue a raw request so the
        # gateway's actual status/body (e.g. policy denial) is visible.
        probe_mcp_raw(mcp_url, access_token)
        raise RuntimeError(f"MCP call failed for {mcp_url}: {detail}") from exc


def get_env_or_exit() -> Tuple[str, str, str, str, str]:
    """Load required environment variables for OAuth 2.1 (PKCE + client credentials) and MCP; exit if missing.

    When SKIP_OAUTH is not set, requires TENANT_URL, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, and MCP_PATH.
    When SKIP_OAUTH is set, requires TENANT_URL and MCP_PATH.

    Returns:
        Tuple of (tenant_url, client_id, client_secret, redirect_uri, mcp_path).
    """
    tenant_url = os.getenv("TENANT_URL", "").strip()
    client_id = os.getenv("CLIENT_ID", "").strip()
    client_secret = os.getenv("CLIENT_SECRET", "").strip()
    redirect_uri = os.getenv("REDIRECT_URI", "").strip()
    mcp_path = os.getenv("MCP_PATH", "").strip()

    def _exit_missing(names: list[str]) -> None:
        print(f"Missing env vars: {', '.join(names)}")
        sys.exit(1)

    if os.getenv("SKIP_OAUTH", "").lower() == "true":
        missing = [name for name, value in [("TENANT_URL", tenant_url), ("MCP_PATH", mcp_path)] if not value]
        if missing:
            _exit_missing(missing)
        return tenant_url, client_id, client_secret, redirect_uri, mcp_path

    required = [("TENANT_URL", tenant_url), ("CLIENT_ID", client_id), ("CLIENT_SECRET", client_secret), ("REDIRECT_URI", redirect_uri), ("MCP_PATH", mcp_path)]
    missing = [name for name, value in required if not value]
    if missing:
        _exit_missing(missing)
    return tenant_url, client_id, client_secret, redirect_uri, mcp_path


async def main() -> None:
    """Entry point: load config, obtain access token, then connect to MCP.

    Loads .env from the script directory. If SKIP_OAUTH is true, uses
    ACCESS_TOKEN from env; otherwise runs the authorization code flow
    (browser, callback server, token exchange). Exits with code 1 on error.
    """
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    tenant_url, client_id, client_secret, redirect_uri, mcp_path = get_env_or_exit()
    base_url = normalize_base_url(tenant_url)
    scope = os.getenv("SCOPE", "full")

    if os.getenv("SKIP_OAUTH", "").lower() == "true":
        _step("Using ACCESS_TOKEN from .env")
        access_token = os.getenv("ACCESS_TOKEN", "dev-token")
    else:
        code_verifier, code_challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(16)
        callback_server = CallbackServer(redirect_uri)
        callback_server.start()
        auth_url = build_authorize_url(base_url, client_id, redirect_uri, scope, code_challenge, state)
        _step("Open this URL to authorize")
        print(auth_url)
        try:
            webbrowser.open(auth_url)
        except Exception:
            pass
        try:
            _step("Waiting for authorization callback")
            code = callback_server.wait_for_code()
        finally:
            callback_server.stop()
        _step("Exchanging code for access token (OAuth 2.1 PKCE + client credentials)")
        t0 = time.perf_counter()
        token = exchange_code_for_token(base_url, client_id, client_secret, code, redirect_uri, code_verifier)
        elapsed = time.perf_counter() - t0
        access_token = token.get("access_token")
        if not access_token:
            raise RuntimeError(f"Token response missing access_token: {token}")
        print(tabulate([("Token exchange", _format_duration(elapsed))], headers=["Step", "Duration"], tablefmt="grid"))
        _print_token_details(access_token)

    try:
        await connect_mcp(base_url, mcp_path, access_token)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
