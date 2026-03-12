#!/usr/bin/env python3
"""OAuth 2.1 + MCP client for CyberArk AI Gateway (Identity bridge).

This script uses OAuth 2.1 with PKCE only (no client secret): authorization code
flow with code_challenge/code_verifier. It then connects to an MCP (Model Context
Protocol) endpoint to list tools and optionally call one. Configuration is via
environment variables (see .env.example).

Environment variables:
    TENANT_URL           Gateway base URL (e.g. https://aigw.example.cloud).
    CLIENT_ID            OAuth client ID.
    CLIENT_SECRET        OAuth client secret (required unless OMIT_CLIENT_SECRET=true).
    REDIRECT_URI         Callback URL (must be registered in CyberArk Identity).
    OMIT_CLIENT_SECRET   If "true", omit client_secret from token request (public client experiment).
    MODE                 If "public", omit client_secret from token request (alternative to OMIT_CLIENT_SECRET).
    MCP_PATH             MCP path (default: /mcp/deep-wiki).
    SCOPE                OAuth scope (default: full).
    SKIP_OAUTH           If "true", use ACCESS_TOKEN from env and skip OAuth.
    ACCESS_TOKEN         Used when SKIP_OAUTH=true.
    TOOL_NAME            Optional MCP tool to call.
    TOOL_ARGS_JSON       Optional JSON object of arguments for the tool.
    LIST_TOOLS           If "false", skip listing tools when TOOL_NAME is set (default: true, always list).

Run Instructions:
    # Normal confidential client (baseline):
    TENANT_URL=https://your-gateway.com
    CLIENT_ID=your-client-id
    CLIENT_SECRET=your-client-secret
    REDIRECT_URI=http://localhost:3030/callback
    SCOPE=full
    python mcp_oauth_client.py

    # Public client experiment (omit client_secret) - either way works:
    TENANT_URL=https://your-gateway.com
    CLIENT_ID=your-client-id
    REDIRECT_URI=http://localhost:3030/callback
    SCOPE=full
    OMIT_CLIENT_SECRET=true
    python mcp_oauth_client.py

    # OR alternatively:
    MODE=public python mcp_oauth_client.py

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
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from dotenv import load_dotenv
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from tabulate import tabulate

# Default MCP path and callback wait timeout (seconds)
DEFAULT_MCP_PATH = "/mcp/deep-wiki"
CALLBACK_TIMEOUT = 300


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


def _unwrap_exception(exc: BaseException) -> BaseException:
    """Recursively get the leaf exception from ExceptionGroups (e.g. from anyio TaskGroup)."""
    while getattr(exc, "exceptions", None) and len(exc.exceptions) > 0:
        exc = exc.exceptions[0]
    return exc


def _print_mcp_error(detail: BaseException, mcp_url: str) -> None:
    """Print a clear, user-friendly MCP error summary with suggested actions."""
    msg = str(detail).strip()
    rows = [("Error", msg)]
    if "504" in msg or "Gateway Time-out" in msg or "timeout" in msg.lower():
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


def _is_loopback_uri(redirect_uri: str) -> bool:
    """Return True if redirect_uri points to a loopback address (localhost, 127.x, [::1])."""
    host = urlparse(redirect_uri).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
    endpoint_suffix: str = "",
    path_prefix: str = "",
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
        endpoint_suffix: Optional suffix appended to the Authorize path (e.g. "-AGAI-1148" for branch stacks).
        path_prefix: Optional path prefix before /OAuth2 (e.g. "/api" for the new IdP bridge).

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
    return f"{base_url}{path_prefix}/OAuth2/Authorize{endpoint_suffix}?{urlencode(params)}"


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the 'code' query param from the OAuth redirect."""

    def __init__(self, *args, callback_data: Dict[str, str], **kwargs):
        self.callback_data = callback_data
        super().__init__(*args, **kwargs)

    def do_GET(self):  # noqa: N802
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)

        # Print callback details
        print(f"\n🔄 OAUTH CALLBACK RECEIVED:")
        print(f"GET {self.path}")
        print(f"Query params: {dict(params)}")

        if "code" in params:
            self.callback_data["code"] = params["code"][0]
            print(f"✅ Authorization code captured: {params['code'][0][:20]}...")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"Authorization complete. You can close this window.")
        else:
            print("❌ No authorization code in callback")
            if "error" in params:
                print(f"Error: {params['error']}")
            if "error_description" in params:
                print(f"Error description: {params['error_description']}")
            self.send_response(400)
            self.end_headers()
        print()  # Extra newline for readability

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
    client_secret: str | None,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    endpoint_suffix: str = "",
    path_prefix: str = "",
) -> Dict[str, str]:
    """Exchange the authorization code for an access token (OAuth 2.1 PKCE + optional client credentials).

    POSTs to the gateway token endpoint with grant_type=authorization_code,
    code_verifier (PKCE), and optionally client_secret. If client_secret is None,
    omits it (public client). If provided, includes it (confidential client).

    Args:
        base_url: Gateway base URL (no trailing slash).
        client_id: OAuth client identifier.
        client_secret: OAuth client secret (None for public clients).
        code: Authorization code from the redirect callback.
        redirect_uri: Same redirect_uri used in the authorize request.
        code_verifier: PKCE code verifier that matches the code_challenge sent at authorize.
        path_prefix: Optional path prefix before /OAuth2 (e.g. "/api" for the new IdP bridge).

    Returns:
        Token response JSON (e.g. access_token, expires_in, refresh_token).

    Raises:
        requests.HTTPError: On non-2xx response from the token endpoint.
    """
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "scope": "full",
    }
    if client_secret is not None:
        data["client_secret"] = client_secret

    token_url = f"{base_url}{path_prefix}/OAuth2/Token{endpoint_suffix}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Print request details
    print(f"\n🔍 TOKEN REQUEST:")
    print(f"POST {token_url}")
    print(f"Headers: {headers}")

    # Show exact POST field names (never show secret values)
    field_names = list(data.keys())
    print(f"📦 POST Fields: {field_names}")

    # Highlight PKCE and client authentication
    pkce_status = f"✅ PKCE: code_verifier present"
    auth_status = "✅ Client Auth: client_secret included" if client_secret else "❌ Client Auth: NO client_secret (public client experiment)"

    print(f"🔐 Authentication Method:")
    print(f"   {pkce_status}")
    print(f"   {auth_status}")

    # Show summary without sensitive values
    summary = {k: "***" if k == "client_secret" else "present" for k in data.keys()}
    print(f"📋 Field Summary: {summary}")

    response = requests.post(
        token_url,
        data=data,
        headers=headers,
        timeout=30,
    )

    # Print response details
    print(f"\n📨 TOKEN RESPONSE:")
    print(f"Status: {response.status_code} {response.reason}")
    print(f"Headers: {dict(response.headers)}")
    try:
        response_json = response.json()
        print(f"Body: {response_json}")
    except Exception:
        print(f"Body (raw): {response.text}")
    print()  # Extra newline for readability

    # Return results for both success and failure cases
    result = {
        "status_code": response.status_code,
        "success": response.status_code == 200,
        "response": response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
    }

    if not result["success"]:
        # Print summary but don't crash - let caller handle
        error_desc = "server-side schema enforcement" if response.status_code == 422 else f"HTTP {response.status_code} error"
        print(f"❌ Token request failed: {error_desc}")
        if response.status_code == 422 and isinstance(result["response"], dict):
            errors = result["response"].get("errors", [])
            if any(err.get("field") == "client_secret" for err in errors):
                print("   CyberArk Identity requires client_secret field (does not support public clients)")

    response.raise_for_status()  # Still raise for proper error handling
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

    # Print MCP connection details
    print(f"\n🔗 MCP CONNECTION:")
    print(f"URL: {mcp_url}")
    print(f"Authorization: Bearer {access_token[:20]}...{access_token[-10:]}")
    print()

    try:
        timings: list[tuple[str, str]] = []
        async with streamablehttp_client(url=mcp_url, headers=headers) as (read_stream, write_stream, _):
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
        raise RuntimeError(f"MCP call failed for {mcp_url}: {detail}") from exc


def get_env_or_exit() -> Tuple[str, str, str, str, str]:
    """Load required environment variables for OAuth 2.1 and MCP; exit if missing.

    When SKIP_OAUTH is not set, requires TENANT_URL, CLIENT_ID, and REDIRECT_URI.
    CLIENT_SECRET is required unless OMIT_CLIENT_SECRET=true or MODE=public.
    MCP_PATH defaults to DEFAULT_MCP_PATH if unset.

    Returns:
        Tuple of (tenant_url, client_id, client_secret, redirect_uri, mcp_path).
    """
    tenant_url = os.getenv("TENANT_URL", "").strip()
    client_id = os.getenv("CLIENT_ID", "").strip()
    client_secret = os.getenv("CLIENT_SECRET", "").strip()
    redirect_uri = os.getenv("REDIRECT_URI", "").strip()
    mcp_path = os.getenv("MCP_PATH", "").strip() or DEFAULT_MCP_PATH

    def _exit_missing(names: list[str]) -> None:
        print(f"Missing env vars: {', '.join(names)}")
        sys.exit(1)

    if os.getenv("SKIP_OAUTH", "").lower() == "true":
        if not tenant_url:
            _exit_missing(["TENANT_URL"])
        return tenant_url, client_id, client_secret, redirect_uri, mcp_path

    required = [("TENANT_URL", tenant_url), ("CLIENT_ID", client_id), ("REDIRECT_URI", redirect_uri)]
    # CLIENT_SECRET is optional only when OMIT_CLIENT_SECRET=true or MODE=public
    omit_secret = (os.getenv("OMIT_CLIENT_SECRET", "").lower() == "true" or
                   os.getenv("MODE", "").lower() == "public")
    if not omit_secret and not client_secret:
        required.append(("CLIENT_SECRET", client_secret))
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
    endpoint_suffix = os.getenv("OAUTH_ENDPOINT_SUFFIX", "").strip()

    # New IdP bridge: port 8443 + /api path prefix
    test_new_idp = os.getenv("TEST_NEW_IDP", "").lower() == "true"
    if test_new_idp:
        from urllib.parse import urlparse, urlunparse
        _parsed = urlparse(base_url)
        oauth_base_url = urlunparse(_parsed._replace(netloc=f"{_parsed.hostname}:8443"))
        oauth_path_prefix = "/api"
    else:
        oauth_base_url = base_url
        oauth_path_prefix = ""

    # Show current mode - support both OMIT_CLIENT_SECRET=true and MODE=public
    omit_secret = (os.getenv("OMIT_CLIENT_SECRET", "").lower() == "true" or
                   os.getenv("MODE", "").lower() == "public")
    if omit_secret:
        print(f"\n🔧 Mode: PUBLIC-CLIENT EXPERIMENT (client_secret omitted)")
        print("   • Will omit client_secret from token request")
        print("   • Testing CyberArk Identity public client support")
    else:
        print(f"\n🔧 Mode: CONFIDENTIAL (client_secret included)")
        print("   • Will include client_secret in token request")
        print("   • Standard confidential client flow")
    print(f"   • Client ID: {client_id}")
    print(f"   • Base URL: {base_url}")
    print(f"   • Scope: {scope}")
    idp_label = "new IdP bridge (:8443/api)" if test_new_idp else "original IdP bridge"
    print(f"   • IdP bridge: {idp_label}")
    print(f"   • Token endpoint: {oauth_base_url}{oauth_path_prefix}/OAuth2/Token{endpoint_suffix}")

    if os.getenv("SKIP_OAUTH", "").lower() == "true":
        _step("Using ACCESS_TOKEN from .env")
        access_token = os.getenv("ACCESS_TOKEN", "dev-token")
    else:
        code_verifier, code_challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(16)
        auth_url = build_authorize_url(oauth_base_url, client_id, redirect_uri, scope, code_challenge, state, endpoint_suffix, oauth_path_prefix)
        loopback = _is_loopback_uri(redirect_uri)

        # Show PKCE pair generation
        print(f"\n🔑 PKCE Generated:")
        print(f"   code_verifier:  {code_verifier[:20]}...")
        print(f"   code_challenge: {code_challenge[:20]}... (SHA256)")
        print(f"   method: S256")

        if loopback:
            # Loopback: start local callback server to capture the code automatically
            callback_server = CallbackServer(redirect_uri)
            callback_server.start()
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
        else:
            # Non-loopback (e.g. https://jojo.com): manual mode — no local server
            _step("Non-loopback redirect URI — manual mode")
            print(f"Redirect URI ({redirect_uri}) is not a loopback address.")
            print("No local callback server will be started.\n")
            _step("Open this URL to authorize")
            print(auth_url)
            try:
                webbrowser.open(auth_url)
            except Exception:
                pass
            print("\nAfter login, your browser will redirect to:")
            print(f"  {redirect_uri}?code=<AUTH_CODE>&state={state}")
            print("\nCopy the 'code' value from the redirect URL and paste it below.")
            print("(If the redirect target is unreachable, copy the code from the browser address bar.)\n")
            code = input("Authorization code: ").strip()
            if not code:
                print("No code provided. Exiting.")
                sys.exit(1)

        omit_secret = (os.getenv("OMIT_CLIENT_SECRET", "").lower() == "true" or
                       os.getenv("MODE", "").lower() == "public")
        client_secret_to_use = None if omit_secret else client_secret

        # PKCE enforcement test: deliberately send wrong code_verifier
        tamper_pkce = os.getenv("TAMPER_PKCE", "").lower() == "true"
        if tamper_pkce:
            import secrets as _secrets
            wrong_verifier = _secrets.token_urlsafe(32)
            print(f"\n⚠️  TAMPER_PKCE=true: replacing code_verifier with a random wrong value")
            print(f"   correct verifier: {code_verifier[:20]}...")
            print(f"   wrong   verifier: {wrong_verifier[:20]}...")
            print(f"   Expected result: Identity should REJECT with invalid_grant or similar")
            code_verifier = wrong_verifier

        mode_desc = "PKCE only (public client experiment)" if omit_secret else "PKCE + client credentials"
        _step(f"Exchanging code for access token (OAuth 2.1 {mode_desc})")
        t0 = time.perf_counter()
        token = exchange_code_for_token(oauth_base_url, client_id, client_secret_to_use, code, redirect_uri, code_verifier, endpoint_suffix, oauth_path_prefix)
        elapsed = time.perf_counter() - t0
        access_token = token.get("access_token")
        if not access_token:
            raise RuntimeError(f"Token response missing access_token: {token}")
        print(tabulate([("Token exchange", _format_duration(elapsed))], headers=["Step", "Duration"], tablefmt="grid"))
        print(f"Access token: {access_token[:10]}...{access_token[-10:]}")

    try:
        await connect_mcp(base_url, mcp_path, access_token)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
