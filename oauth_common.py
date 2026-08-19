#!/usr/bin/env python3
"""Shared helpers for the CyberArk AI Gateway OAuth examples.

Small, dependency-light utilities used by both mcp_oauth_client.py and
token_exchange_demo.py: console output, TLS toggle, base-URL normalization,
and JWT decoding / token pretty-printing.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

import requests
from tabulate import tabulate

# Claims most relevant to whether a resource will accept a token.
_INTERESTING_CLAIMS = ("iss", "aud", "scope", "scp", "sub", "client_id", "azp", "agent_name")


def step(msg: str) -> None:
    """Print a step label to stdout."""
    print(f"\n==> {msg}")


def verify_tls() -> bool:
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


def format_duration(seconds: float) -> str:
    """Format a duration in seconds for display (e.g. 1.23s or 456 ms)."""
    if seconds >= 1.0:
        return f"{seconds:.2f}s"
    return f"{seconds * 1000:.0f} ms"


def normalize_base_url(tenant_url: str) -> str:
    """Normalize the tenant URL for use in OAuth and MCP requests.

    Ensures a scheme (https if missing), strips whitespace, and removes
    a trailing slash. Raises if the value is empty.
    """
    if not tenant_url or not tenant_url.strip():
        raise ValueError("TENANT_URL is required")
    base = tenant_url.strip()
    if not base.startswith(("http://", "https://")):
        base = f"https://{base}"
    return base.rstrip("/")


def decode_jwt_segment(segment: str) -> dict[str, Any]:
    """Base64url-decode a single JWT segment (header or payload) into a dict."""
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode()))


def print_token_details(access_token: str) -> None:
    """Print the full access token and, if it is a JWT, its decoded claims.

    Helps diagnose why a token is rejected: check aud (audience/resource),
    scope, iss (issuer), and exp (expiry) against what the resource expects.
    """
    print(f"Access token (full):\n{access_token}\n")
    parts = access_token.split(".")
    if len(parts) != 3:
        print("Token is not a JWT (opaque token) — cannot decode claims locally.")
        return
    try:
        header = decode_jwt_segment(parts[0])
        payload = decode_jwt_segment(parts[1])
    except Exception as exc:  # noqa: BLE001
        print(f"Could not decode JWT: {exc}")
        return
    print("JWT header:")
    print(json.dumps(header, indent=2, sort_keys=True))
    print("JWT claims:")
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))

    rows: list[tuple[str, str]] = [(c, str(payload[c])) for c in _INTERESTING_CLAIMS if c in payload]

    # Verdict: locally we can only check structure + expiry (signature needs the
    # issuer's JWKS). Report expiry explicitly and note the limits of a local check.
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        remaining = exp - time.time()
        expired = remaining < 0
        rows.append(("exp", f"EXPIRED {abs(remaining):.0f}s ago" if expired else f"valid for {remaining:.0f}s"))
    else:
        expired = False
        rows.append(("exp", "not present"))

    if expired:
        verdict = "INVALID — token has expired; run the OAuth flow again."
    else:
        verdict = ("VALID (structurally): well-formed JWT, not expired. NOTE: signature/audience "
                   "not verified locally — only the gateway can fully validate.")
    rows.append(("Token verdict", verdict))
    print("\n" + tabulate(rows, headers=["Claim", "Value"], tablefmt="grid"))
