# SAI Code Examples

## Purpose

This project provides **code examples and reference material** for integrating with the CyberArk AI Gateway. It shows how to:

- **Authenticate** via **OAuth 2.1** (authorization code flow with **PKCE** and **client credentials**) against the gateway and CyberArk Identity.
- **Call MCP Server (Model Context Protocol)** endpoints—such as **deep-wiki** and **SIA** (Secure Infrastructure Access)—using a Bearer token.

**This project supports only OAuth 2.1.** The primary flow uses the authorization code flow with **PKCE** (code_challenge/code_verifier) and **client_id** + **client_secret** on the token request. It also includes experimental modes for testing public client support (PKCE without client_secret) and PKCE enforcement validation (deliberate code_verifier tampering).

The examples are intended for developers building agents, IDEs, or tools that need to use the gateway’s OAuth 2.1 and MCP APIs. Use them as a starting point for your own clients and automation.

## Project files

| File or folder | Description |
|----------------|-------------|
| **`mcp_oauth_client.py`** | Main Python script. Runs the OAuth 2.1 authorization code flow with PKCE and client credentials (browser, callback server, code exchange with `code_verifier` and `client_secret`), then connects to the MCP gateway to initialize, list tools, and optionally call a tool. |
| **`openapi.yaml`** | OpenAPI 3.1 specification for the Agents Service IdP Bridge (OAuth and `.well-known` endpoints). |
| **`.env.example`** | Template for environment variables. Copy to `.env` and set `TENANT_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`, and optional `TOOL_NAME`, `TOOL_ARGS_JSON`, `LIST_TOOLS`, `SKIP_OAUTH`, `ACCESS_TOKEN`, `OMIT_CLIENT_SECRET`, `MODE`, `OAUTH_ENDPOINT_SUFFIX`, `TAMPER_PKCE`. |
| **`.env`** | Local configuration (not committed). Holds tenant URL, OAuth credentials, redirect URI, and other options. |
| **`README.md`** | This file. Setup, agent registration, redirect URI configuration, troubleshooting, and a short OAuth 2.1 + MCP reference. |
| **`pyproject.toml`** | Project metadata and dependencies for the Python package (e.g. when using `uv` or `pip install -e .`). |
| **`requirements.txt`** | Pinned dependencies for installing with `pip install -r requirements.txt`. |
| **`uv.lock`** | Lock file for [uv](https://github.com/astral-sh/uv); used when installing with `uv sync`. |
| **`.gitignore`** | Ignores `.env`, virtualenvs, and other local/generated files. |
| **`docs/`** | Documentation folder. |
| **`docs/OAUTH2_AND_MCP_GUIDE.md`** | Detailed OAuth 2.1 endpoints (Authorize with PKCE, Token with code_verifier, Refresh), MCP gateway usage, custom agent testing, and Q&A with cURL and Python examples. |

## Setup

**Prerequisites:** Python 3.10 or newer.

Copy `.env.example` to `.env` and fill in your credentials (tenant URL, OAuth client ID, client secret, redirect URI). Authentication uses OAuth 2.1 with PKCE and client credentials.

### Using pip (virtual environment)

Create and activate a virtual environment, then install dependencies from `requirements.txt`:

**Linux / macOS:**

```bash
# Create the virtual environment
python3 -m venv .venv

# Activate it (required before installing or running the client)
source .venv/bin/activate

# Optional: upgrade pip inside the venv
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

**Windows (Command Prompt):**

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

After activation, your prompt will show `(.venv)`. To leave the virtual environment, run `deactivate`.

### Using uv

```bash
uv venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt
```

Or install from the project (editable) with uv:

```bash
uv venv && source .venv/bin/activate
uv pip install -e .
```

### Run the Python client

From the project root (with your venv activated):

```bash
python mcp_oauth_client.py
```

To bypass OAuth and use an existing token, set `SKIP_OAUTH=true` and `ACCESS_TOKEN=...` in `.env`.

### Run modes

The script supports several run modes via environment variables:

| Mode | How to enable | What it does |
|------|---------------|--------------|
| **Confidential client** (default) | `CLIENT_SECRET=...` in `.env` | Standard flow — sends `client_id` + `client_secret` + PKCE `code_verifier` in the token request. |
| **Public client experiment** | `OMIT_CLIENT_SECRET=true` or `MODE=public` | Omits `client_secret` from the token request. Tests whether CyberArk Identity accepts PKCE-only (no secret) token exchanges. |
| **PKCE enforcement test** | `TAMPER_PKCE=true` | Deliberately replaces the correct `code_verifier` with a random wrong value before the token request. Verifies that Identity correctly rejects a tampered verifier with `invalid_grant`. |
| **Skip OAuth** | `SKIP_OAUTH=true` + `ACCESS_TOKEN=...` | Skips the browser flow and uses a pre-existing Bearer token directly. |
| **Branch stack** | `OAUTH_ENDPOINT_SUFFIX=-<suffix>` | Appends a suffix to the Authorize and Token endpoint paths (e.g. `/OAuth2/Authorize-AGAI-1148`). Used for testing feature-branch deployments. |

### How to create an AI agent (Secure AI)

To use this client with the CyberArk AI Gateway, register an AI agent and obtain client credentials:

1. Log in to your **CyberArk Administration** tenant.
2. From the main menu, click **Secure AI agents**.
3. On the AI agents page, click **Register AI agent**.
4. Fill in the agent details as in the table below (full steps: [Register AI agent](https://docs.cyberark.com/admin-space/latest/en/content/secureai/registeragent.htm)).

| Field | Description |
|-------|-------------|
| **Agent name** | Unique name (2–256 characters). Letters, numbers, spaces, hyphens, underscores. |
| **Agent type** | Predefined (e.g. Claude, Gemini, Custom) or **Custom** to use your own redirect URL. |
| **Redirect URL** | At least one valid HTTPS URL where the agent receives the OAuth 2.1 authorization code (e.g. `https://…/oauth/callback`). Up to 10 URLs, max 2,048 characters each. No wildcards or fragments. For local dev, you also register an HTTP redirect in Identity (see next section). |
| **Description** | Short description (up to 500 characters). |
| **Owner** | Business or technical owner (min 2 characters). |
| **Tags** | Optional key-value tags (up to 10, 1–30 characters each). |

5. Click **Save and continue to configuration** and complete the wizard to get your **Client ID** and **Client secret** for `.env`.

### Callback redirect URL and local development

The OAuth 2.1 flow sends the user’s browser back to a **redirect URL** after they approve access. The Python client runs a local HTTP server on that URL to receive the authorization code.

- Set **`REDIRECT_URI`** in `.env` to the exact URL your client uses. For local runs use **`REDIRECT_URI=http://localhost:3030/callback`** (the client binds to that host and port).
- **Register this same URL in CyberArk Identity** so the authorize request is accepted. For an **OpenID Connect** application (or the app that backs your AI agent):
  1. In **Identity Administration**, go to **Apps & Widgets → Web Apps**, add or open a **Custom → OpenID Connect** application.
  2. Open the **Trust** page.
  3. Under **Authorized Redirect URIs**, add **`http://localhost:3030/callback`** (or the exact value you use in `.env`). At least one redirect URI is required.
  4. Leave **Enable full URI match** selected for exact matching.
  5. Save. Use the **OpenID Connect Client ID** and client secret as `CLIENT_ID` and `CLIENT_SECRET` in `.env`.

Reference: [Add and configure the custom OpenID Connect application](https://docs.cyberark.com/identity/latest/en/content/applications/appscustom/openidaddconfigapp.htm).

Use the same redirect URI in `.env` and in Identity (same scheme, host, port, and path).

### Troubleshooting

- **504 Gateway Time-out** — The gateway (or the MCP backend behind it) did not respond within its timeout. Common causes: the tool is slow (e.g. AI-backed tools), the gateway’s timeout is too short, or the backend is overloaded. Try again, use a faster/simpler tool, or ask the gateway admin to raise timeouts.
- **Invalid params / missing properties** — The tool requires arguments. Set `TOOL_ARGS_JSON` in `.env` with the required keys (see `.env.example` for examples).
- **401 Unauthorized** — Token expired or invalid. Run the OAuth flow again (without `SKIP_OAUTH`) to get a new token.
- **403 on the Authorize URL (CloudFront WAF)** — The CloudFront WAF rule `EC2MetaDataSSRF_QUERYARGUMENTS` can block the authorize request when `redirect_uri` contains `localhost` or `127.0.0.1`. This fires before reaching the IdP bridge. Fixed by adding SSRF exclusions to the ALB WAF CDK construct (`alb_waf_construct.py`) and redeploying across all environments.
- **422 on the token request (IdP bridge schema validation)** — The IdP bridge enforces `client_secret` as a required field before forwarding to CyberArk Identity. If running with `OMIT_CLIENT_SECRET=true`, the bridge rejects the request with a 422 schema error before Identity is reached. This means the public client experiment is blocked at the bridge layer, not Identity.

---

## OAuth 2.1 + MCP Quick Guide

### Endpoints

Authorize:
<tenant-url>/OAuth2/Authorize
Example: https://aigw-mgogax.data.aigw.integration-cyberark.cloud/OAuth2/Authorize

Token:
<tenant-url>/OAuth2/Token
Example: https://aigw-mgogax.data.aigw.integration-cyberark.cloud/OAuth2/Token

MCP:
<tenant-url>/mcp/deep-wiki
<tenant-url>/mcp/sia
Examples:
https://aigw-mgogax.data.aigw.integration-cyberark.cloud/mcp/deep-wiki
https://aigw-mgogax.data.aigw.integration-cyberark.cloud/mcp/sia

Well-known:
<tenant-url>/.well-known/oauth-authorization-server
<tenant-url>/.well-known/oauth-protected-resource

Notes:
- Refresh tokens are supported; use `grant_type=refresh_token` at the token endpoint (see docs/OAUTH2_AND_MCP_GUIDE.md).
- OpenID configuration is not supported.
- Supported scope: full.

MCP usage
---------

- Get an access token from /OAuth2/Token.
- POST JSON-RPC to the MCP endpoint.
- Headers: Authorization: Bearer <access_token>, Content-Type: application/json.
- deep-wiki: MCP tools exposed by the Deep Wiki integration.
- sia: CyberArk MCP server for secure infrastructure access for databases.

Examples
--------

Authorize URL (OAuth 2.1 PKCE: include code_challenge, code_challenge_method=S256, state):
<tenant-url>/OAuth2/Authorize?client_id=<CLIENT_ID>&response_type=code&redirect_uri=<REDIRECT_URI>&scope=full&code_challenge=<CODE_CHALLENGE>&code_challenge_method=S256&state=<STATE>

Token (authorization_code with PKCE + client credentials — confidential client):
curl -X POST "<tenant-url>/OAuth2/Token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=<CLIENT_ID>" \
  --data-urlencode "client_secret=<CLIENT_SECRET>" \
  --data-urlencode "code=<AUTH_CODE>" \
  --data-urlencode "redirect_uri=<REDIRECT_URI>" \
  --data-urlencode "code_verifier=<CODE_VERIFIER>" \
  --data-urlencode "scope=full"

Token (authorization_code with PKCE only — public client experiment, omit client_secret):
curl -X POST "<tenant-url>/OAuth2/Token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=<CLIENT_ID>" \
  --data-urlencode "code=<AUTH_CODE>" \
  --data-urlencode "redirect_uri=<REDIRECT_URI>" \
  --data-urlencode "code_verifier=<CODE_VERIFIER>" \
  --data-urlencode "scope=full"

MCP call (deep-wiki):
curl -X POST "<tenant-url>/mcp/deep-wiki" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}'

MCP call (sia):
curl -X POST "<tenant-url>/mcp/sia" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}'
