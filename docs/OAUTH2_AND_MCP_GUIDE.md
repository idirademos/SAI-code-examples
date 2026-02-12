# OAuth 2.1 and MCP Gateway – Documentation and Q&A

This document describes the CyberArk AI Gateway **OAuth 2.1** endpoints and MCP (Model Context Protocol) gateway. **This project supports only OAuth 2.1.** Authentication uses the authorization code flow with **PKCE** and **client credentials** (client_id + client_secret); they do not conflict. It is intended for developers integrating custom agents or clients with the gateway. Content is based on this repository’s code and the OpenAPI spec.

**How to use this doc:** Replace the example tenant host (`infycpc2024.data.aigw.cyberark.cloud`) with your own tenant base URL. Section 1 describes each endpoint; Section 4 provides copy-paste examples.

---

## Contents

1. [OAuth 2.1 Endpoints](#1-oauth-21-endpoints--documentation-and-implementation)  
2. [Custom Agent Testing and OAuth 2.1 Implementation](#2-custom-agent-testing-and-oauth-21-implementation)  
3. [Technical Q&A](#3-specific-technical-questions)  
4. [Working Examples](#4-working-examples)

---

## 1. OAuth 2.1 Endpoints – Documentation and Implementation

**This project supports only OAuth 2.1.** The authorization code flow uses **PKCE** and **client credentials**. Send `code_challenge` and `code_challenge_method=S256` on the authorize request; send `code_verifier` and `client_secret` on the token request. PKCE and client secret do not conflict.

### A. Authorization Endpoint

Where the user signs in and approves access. Your app redirects the user here; after success, the user is redirected back to your `redirect_uri` with an authorization `code` and the same `state` you sent.

**URL (pattern):** `https://<tenant-host>/OAuth2/Authorize`  
**Example:** `https://infycpc2024.data.aigw.cyberark.cloud/OAuth2/Authorize`

| Item | Details |
|------|---------|
| **HTTP method** | `GET` |
| **Headers** | None required; browser/user-agent sends the request. |
| **Parameters (query)** | All passed as query string. |
| **Required** | `client_id`, `code_challenge`, `code_challenge_method` (PKCE), `state`. |
| **Recommended** | `response_type=code`, `redirect_uri`, `scope`. |

**Query parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `client_id` | Yes | OAuth client identifier (UUID from CyberArk Identity). |
| `response_type` | Recommended | Use `code` for authorization code flow. |
| `redirect_uri` | Recommended | Must match a redirect URI registered for the client in CyberArk Identity. |
| `scope` | Recommended | Supported value: **`full`**. |
| `state` | Yes | Opaque value for CSRF protection; returned unchanged in the redirect. |
| `code_challenge` | Yes (OAuth 2.1 PKCE) | Base64url(SHA256(code_verifier)). |
| `code_challenge_method` | Yes (OAuth 2.1 PKCE) | Use `S256`. |

**Responses:**

| Status | Meaning |
|--------|---------|
| **307** | Redirect to Identity login; after success, user is sent to `redirect_uri?code=<AUTH_CODE>&state=<STATE>` (or error in query). |
| **400** | Bad request (e.g. invalid or missing `client_id`). |
| **500** | Server error. |

**Scope:** Use **`scope=full`** for MCP access. This is the only scope documented as supported for this gateway.

---

### B. Token Endpoint

Where your app exchanges the authorization `code` for an **access token**. **OAuth 2.1:** send both `code_verifier` (PKCE) and `client_secret`; they do not conflict.

**URL (pattern):** `https://<tenant-host>/OAuth2/Token`  
**Example:** `https://infycpc2024.data.aigw.cyberark.cloud/OAuth2/Token`

| Item | Details |
|------|---------|
| **HTTP method** | `POST` |
| **Content-Type** | **`application/x-www-form-urlencoded`** (not JSON). |
| **Body** | Form-encoded key-value pairs. |

**Grant types:** **`authorization_code`** (exchange the code for tokens using PKCE + client credentials) and **`refresh_token`** (see Section C).

**Required parameters (authorization_code grant, OAuth 2.1 PKCE + client credentials):**

| Parameter | Description |
|-----------|-------------|
| `grant_type` | `authorization_code` |
| `client_id` | OAuth client identifier (UUID). |
| `client_secret` | OAuth client secret. |
| `code` | Authorization code from the redirect after the user authorizes. |
| `redirect_uri` | Same value used in the authorization request. |
| `code_verifier` | PKCE code verifier (plain string that hashes to the `code_challenge` sent at authorize). |
| `scope` | e.g. `full`. |

**Responses:**

| Status | Meaning |
|--------|---------|
| **200** | Success. JSON body includes `access_token` (use as Bearer token), and may include `expires_in` (seconds), `token_type` (e.g. `Bearer`), and `refresh_token`. |
| **400** | Invalid request (e.g. invalid or expired `code`, wrong `redirect_uri`, or invalid `code_verifier`). |
| **401** | Invalid `client_id`, `client_secret`, or `code_verifier`. |
| **500** | Server error. |

**Token lifetime:** Determined by CyberArk Identity. Check the `expires_in` value in the 200 response, or ask your gateway/Identity administrator.

---

### C. Refresh Token

**URL:** Same as the token endpoint: `https://<tenant-host>/OAuth2/Token`

When the token response includes a **`refresh_token`**, you can use it to obtain a new access token without asking the user to sign in again.

**Request:** `POST` to the token endpoint with `Content-Type: application/x-www-form-urlencoded`.

**Required parameters (refresh_token grant):**

| Parameter       | Description |
|----------------|-------------|
| `grant_type`   | `refresh_token` |
| `refresh_token`| The refresh token from a previous token response. |
| `client_id`    | OAuth client identifier (UUID). |

**Note:** This project sends both PKCE and client_secret for the authorization_code grant; for refresh_token, use `client_id` and `client_secret`.

**Optional:** `scope` (e.g. `full`). Some tenants may require the same scope as the original request.

**Response:** Same shape as the authorization_code response: `access_token`, optionally `expires_in`, `token_type`, and possibly a new `refresh_token`. Refresh token expiration policy is determined by CyberArk Identity; confirm with your gateway administrator.

**When the refresh token expires or is invalid:** Run the authorization code flow again (redirect the user to `/OAuth2/Authorize` with PKCE, get a new `code`, exchange at `/OAuth2/Token` with `code_verifier`).

---

### D. MCP Gateway

The MCP (Model Context Protocol) gateway is the HTTP API your agent calls to list and invoke tools. Every request must include a valid access token from the OAuth 2.1 (PKCE) flow.

**URLs:** One POST endpoint per path. Use the base MCP path or a path-specific one, depending on your tenant:

- `https://<tenant-host>/mcp` — common when the gateway routes to multiple backends
- `https://<tenant-host>/mcp/deep-wiki` — Deep Wiki tools
- `https://<tenant-host>/mcp/sia` — SIA (Secure Infrastructure Access) tools  

**Example:** `https://infycpc2024.data.aigw.cyberark.cloud/mcp`

| Item | Details |
|------|---------|
| **Method** | `POST` |
| **Content-Type** | `application/json` |
| **Authentication** | `Authorization: Bearer <access_token>` |

**Request body:** JSON-RPC 2.0. Required fields: `jsonrpc` (e.g. `"2.0"`), `id` (string or number), `method` (string), `params` (object or array).

**Common methods:**

| Method | Purpose |
|--------|---------|
| **initialize** | Handshake; returns server info and capabilities. |
| **tools/list** | List available tools. |
| **tools/call** | Run a tool by name with optional `arguments` object. |

**Response:** JSON-RPC 2.0. Success: `result`. Failure: `error` with `code` and `message` (e.g. invalid params, missing tool arguments).

**HTTP and MCP errors:**

| HTTP | Meaning | What to do |
|------|---------|------------|
| **200** | Request accepted. Body may be success or JSON-RPC error. | Parse JSON; if `error` is present, handle (e.g. fix arguments and retry). |
| **401** | Unauthorized. | Get a new access token via the authorization code flow. |
| **500** | Server/gateway error. | Retry or contact gateway admin. |
| **504** | Gateway time-out. | Retry, use a lighter tool, or ask admin to increase timeouts. |

Tool-level errors (e.g. missing required arguments like `repoName`, `question`) appear in the response body as JSON-RPC `error`, not as HTTP 4xx.

---

## 2. Custom Agent Testing and OAuth 2.1 Implementation

This section addresses typical issues when building a custom agent that does not use a built-in OAuth 2.1 library: why “pending connection” happens, how to test locally, how to implement the flow, and how to debug.

### Why do I get “pending connection” or “not supported HTTP”?

**Short answer:** The gateway requires a valid **Bearer access token** on every MCP request. That token is only obtained by completing the **OAuth 2.1** **authorization code** flow with **PKCE** (code_challenge at authorize, code_verifier at token) and **client credentials** (client_id, client_secret). Your app must perform the flow and send both PKCE and client_secret on the token request.

The gateway expects:

1. A **browser (or redirect)** to hit the Authorization endpoint so the user can log in and approve.
2. Your app to receive the **authorization code** at `redirect_uri`.
3. Your app to **exchange** that code at the Token endpoint for an **access_token**.
4. That **access_token** to be sent as **Bearer** on every MCP request.

Without steps 1–3, there is no token; without step 4, MCP returns 401. You must implement the flow that uses the parameters in `.env`.

### How to test the OAuth 2.1 flow locally

1. **Use this repo’s Python client** (recommended):
   - Copy `.env.example` to `.env`.
   - Set `TENANT_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI` (and optionally `MCP_PATH`, `TOOL_NAME`, `TOOL_ARGS_JSON`). OAuth 2.1 uses PKCE + client credentials.
   - Ensure `REDIRECT_URI` is registered in CyberArk Identity (e.g. `http://localhost:3030/callback`). For OpenID Connect apps, add it under **Trust → Authorized Redirect URIs**. See [Add and configure the custom OpenID Connect application](https://docs.cyberark.com/identity/latest/en/content/applications/appscustom/openidaddconfigapp.htm).
   - Run: `python mcp_oauth_client.py`.
   - The script opens the browser for login, captures the code, exchanges it for a token, and calls MCP. Use it to verify credentials and redirect URI.

2. **Test with cURL (manual flow):**
   - Open the Authorize URL in a browser (Section 4), log in, and copy the `code` from the redirect URL.
   - Exchange the code for a token using the Token cURL example in Section 4.
   - Call MCP with the returned `access_token` (Section 4).

3. **Local redirect URI:** Use a URL your machine can receive (e.g. `http://localhost:3030/callback`). The Python client runs a small HTTP server on that host/port to capture the code. Your custom agent must do the same, or use a loopback URL where you can read the `code` from the query string.

### How to implement an OAuth 2.1 client from scratch

Implement these steps in order:

1. **Authorization request:** Generate PKCE `code_verifier` and `code_challenge` (S256). Build the Authorize URL with `client_id`, `response_type=code`, `redirect_uri`, `scope=full`, `code_challenge`, `code_challenge_method=S256`, and `state`. Open it in a browser or redirect the user.
2. **Receive code:** On the configured `redirect_uri`, read the `code` and `state` from the query string.
3. **Token request:** `POST` to `/OAuth2/Token` with `Content-Type: application/x-www-form-urlencoded` and body: `grant_type=authorization_code`, `client_id`, `client_secret`, `code`, `redirect_uri`, `code_verifier`, `scope=full`.
4. **Parse token response:** Read `access_token` (and optionally `expires_in`) from the JSON response.
5. **Call MCP:** For every MCP request, set header `Authorization: Bearer <access_token>` and send JSON-RPC in the body.

See the Python script `mcp_oauth_client.py` in this repo for a full reference implementation.

### Token caching and refresh

- **Caching:** Store the `access_token` (and `expires_in` if present) in memory or secure storage. Reuse it for all MCP requests until it expires.
- **Refresh:** If the token response includes a **`refresh_token`**, store it securely. When the access token expires (or you get 401), call the token endpoint with `grant_type=refresh_token` and the stored `refresh_token` to get a new access token (and possibly a new refresh token). When the refresh token is no longer valid, run the authorization code flow again.

### How to debug authentication without production access

1. **Use a non-production tenant** if CyberArk provides one (e.g. integration or sandbox), with the same OAuth 2.1 and MCP endpoints.
2. **Verify .env:** Ensure `TENANT_URL`, `CLIENT_ID`, `CLIENT_SECRET`, and `REDIRECT_URI` match the Identity application; `REDIRECT_URI` must be exactly registered.
3. **Test with this repo:** Run `mcp_oauth_client.py` with your `.env`. If it works, your credentials and redirect URI are correct; the issue is in the custom agent’s flow.
4. **Bypass OAuth for MCP-only debugging:** Set `SKIP_OAUTH=true` and `ACCESS_TOKEN=<valid_token>` in `.env`, then run the client. This checks MCP connectivity and token format without running the full OAuth flow (obtain the token once via browser + cURL or the Python script).
5. **Discovery:** Call `GET https://<tenant>/.well-known/oauth-authorization-server` to confirm authorization and token endpoint URLs and supported grant types.

---

## 3. Specific Technical Questions

| Question | Answer |
|----------|--------|
| **What scope is required for MCP?** | Use **`full`**. This is the only scope documented as supported for this gateway. OpenID/profile are not required for MCP. |
| **What is the access token lifetime?** | Set by CyberArk Identity. Check the `expires_in` field in the token response, or ask your gateway/Identity administrator. |
| **Can I use the same token for parallel requests?** | Yes. One access token can be used for multiple concurrent MCP (or other API) calls. No special locking is needed. |
| **Is my Client ID correctly configured for MCP?** | It must be a UUID registered in CyberArk Identity, with the **exact** `redirect_uri` you use, and allowed for OAuth 2.1 and MCP per your tenant. If Authorize and Token succeed but MCP returns 401, confirm with the gateway admin that your client is enabled for MCP. |

**Error handling quick reference:**

| Situation | What you see | What to do |
|-----------|----------------|------------|
| Invalid or expired token | HTTP 401 on MCP | Re-run the authorization code flow to get a new token. |
| Wrong client credentials or invalid code_verifier | HTTP 401 on Token request | Check `client_id`, `client_secret`, and that `code_verifier` matches the `code_challenge` sent at authorize. |
| Invalid code, wrong redirect_uri, or invalid code_verifier | HTTP 400 on Token request | Use the same `redirect_uri` and `code_verifier` as in the Authorize step; use the code once and before it expires. |
| Missing/invalid tool arguments | HTTP 200 with JSON-RPC `error` | Read `error.message`; add or fix parameters (e.g. `repoName`, `question` for Deep Wiki tools). |
| Gateway or backend timeout | HTTP 504 | Retry, use a lighter tool, or ask the admin to increase timeouts. |

---

## 4. Working Examples

Copy-paste examples using the endpoints described in Section 1. Replace the tenant host and credentials with your own.

### Variables (set these first)

```bash
TENANT="https://infycpc2024.data.aigw.cyberark.cloud"
CLIENT_ID="your-client-id-uuid"
CLIENT_SECRET="your-client-secret"
REDIRECT_URI="http://localhost:3030/callback"
# OAuth 2.1: PKCE (code_verifier/code_challenge) + client_secret. Generate code_verifier and code_challenge (see Python client or RFC 7636).
```

### Step 1: Get an authorization code

Generate a PKCE `code_verifier` (e.g. 32 random bytes, base64url) and `code_challenge = base64url(sha256(code_verifier))`. Open the authorize URL in a browser with `code_challenge`, `code_challenge_method=S256`, and `state`. After login, you will be redirected to `REDIRECT_URI?code=...&state=...`. Copy the `code` value.

```bash
# Example (replace CODE_CHALLENGE and STATE with values you generated):
echo "${TENANT}/OAuth2/Authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=full&code_challenge=CODE_CHALLENGE&code_challenge_method=S256&state=STATE"
# Open the printed URL in a browser; after login, copy the 'code' from the redirect URL.
```

### Step 2: Exchange the code for an access token (PKCE + client credentials)

Replace `AUTH_CODE` with the code from Step 1 and `CODE_VERIFIER` with the same code_verifier used to produce the code_challenge in Step 1.

```bash
curl -s -X POST "${TENANT}/OAuth2/Token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "code=AUTH_CODE" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" \
  --data-urlencode "code_verifier=CODE_VERIFIER" \
  --data-urlencode "scope=full"
```

**Sample success response (may include `refresh_token`):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Refresh the access token (when it expires):**

```bash
# Use the refresh_token from the initial token response.
curl -s -X POST "${TENANT}/OAuth2/Token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=YOUR_REFRESH_TOKEN" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "scope=full"
```

**Sample error (400):**

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired or invalid."
}
```

### Step 3: Call MCP – list tools

Use the `access_token` from Step 2.

```bash
ACCESS_TOKEN="paste_access_token_here"
curl -s -X POST "${TENANT}/mcp" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list","params":{}}'
```

**Sample success (structure):**

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "tools": [
      {
        "name": "ask_question__deepwiki_github",
        "description": "Proxied version of ask_question...",
        "inputSchema": { ... }
      }
    ]
  }
}
```

**Sample error (401):**

```text
HTTP/1.1 401 Unauthorized
```

**Sample MCP error (200 with JSON-RPC error):**

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "error": {
    "code": -32602,
    "message": "invalid params: validating \"arguments\": required: missing properties: [\"repoName\", \"question\"]"
  }
}
```

### Step 4: Call MCP – invoke a tool

Example: call the SIA tool `list_database_targets__sia_mcp` (no arguments required).

```bash
curl -s -X POST "${TENANT}/mcp" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"2","method":"tools/call","params":{"name":"list_database_targets__sia_mcp","arguments":{}}}'
```

### Python snippet (minimal OAuth 2.1 PKCE + client credentials + MCP)

For a complete flow (browser, code capture, PKCE + client_secret token exchange, MCP with initialize/tools/list/call_tool), use `mcp_oauth_client.py` in this repo. Minimal pattern for token exchange and one MCP call:

```python
import requests

# 1. After user authorizes, you have 'code' from redirect_uri query. Use the same code_verifier you sent as code_challenge at authorize.
code = "..."  # from redirect
code_verifier = "..."  # the PKCE code_verifier (must match code_challenge sent at authorize)
token_resp = requests.post(
    f"{TENANT}/OAuth2/Token",
    data={
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        "scope": "full",
    },
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    timeout=30,
)
token_resp.raise_for_status()
access_token = token_resp.json()["access_token"]

# 2. Call MCP
mcp_resp = requests.post(
    f"{TENANT}/mcp",
    headers={
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    },
    json={"jsonrpc": "2.0", "id": "1", "method": "tools/list", "params": {}},
    timeout=60,
)
mcp_resp.raise_for_status()
print(mcp_resp.json())
```

---

## Summary

| Topic | Answer |
|-------|--------|
| **Authorization** | GET `/OAuth2/Authorize` with `client_id`, `response_type=code`, `redirect_uri`, `scope=full`, `code_challenge`, `code_challenge_method=S256`, `state`. |
| **Token** | POST `/OAuth2/Token` with `grant_type=authorization_code`, `client_id`, `client_secret`, `code`, `redirect_uri`, `code_verifier`, `scope` (PKCE + client credentials). |
| **Refresh** | Supported. Use `grant_type=refresh_token` at the token endpoint with `client_id` and `client_secret`. |
| **MCP** | POST to `/mcp` (or `/mcp/deep-wiki`, `/mcp/sia`) with `Authorization: Bearer <access_token>` and a JSON-RPC body. |
| **Scope** | Use `full`. |
| **Testing** | Use this repo’s Python client and `.env`; ensure the redirect URI is registered in CyberArk Identity and matches exactly. |

For tenant-specific limits (token lifetime, timeouts, allowed clients), see CyberArk Identity and gateway administration documentation or support.
