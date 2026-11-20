# Gemini Connect

An unofficial Model Context Protocol (MCP) server for Antigravity. Connect a Google account, discover the models and quotas it can access, and send text prompts from an MCP client.

[Setup](#setup) · [MCP tools](#mcp-tools) · [Cookies and account data](#cookies-and-account-data) · [Development](#development)

## Setup

This repository contains the server source. Each deployment needs its own authenticated OpenAI Sites Worker environment, a D1 database, and an Antigravity OAuth configuration. Model availability and quotas depend on the connected account.

### 1. Configure the Worker

Apply the SQL migration in [`drizzle/`](drizzle/) to the deployment's D1 database.

| Setting | What to provide |
| --- | --- |
| `DB` | D1 database binding |
| `SITE_ORIGIN` | Exact HTTPS origin of the deployment, without a trailing slash |
| `TOKEN_ENCRYPTION_KEY` | A fresh 32-byte base64url key stored as a runtime secret |
| `ANTIGRAVITY_CLIENT_ID` and `ANTIGRAVITY_CLIENT_SECRET` | OAuth client configuration stored as runtime secrets. See the [protocol reference](THIRD_PARTY_LICENSES.md). |

Generate the encryption key locally and put it directly into your host's secret store.

```sh
node -p "require('node:crypto').randomBytes(32).toString('base64url')"
```

The Worker trusts the identity headers supplied by Sites. On another host, restrict access to a trusted authentication layer that strips caller-supplied identity headers and injects a verified identity.

### 2. Deploy and connect

1. Run `npm run build` and deploy `dist/` using your hosting project's configuration.
2. Open `/antigravity` on your deployment while signed in and complete Google consent.
3. Paste the loopback return URL into the deployment's protected completion form. Keep the URL out of chat, logs, and issue reports.
4. Configure your MCP client to use your deployment's authenticated `/mcp` endpoint. Call `list_models` to discover model IDs and `test_request` to verify generation.

The optional Google profile flow at `/settings` uses its own Web OAuth client and an `/oauth/callback` redirect URI.

## MCP tools

| Tool | What it does |
| --- | --- |
| `account_status` | Checks the connection and provider access |
| `list_models` | Returns model IDs available to the connected account |
| `usage_limits` | Shows quota information supplied by Antigravity |
| `generate_text` | Sends a prompt to a selected model |
| `test_request` | Makes a small generation request to verify access |
| `disconnect` | Deletes the stored connection and attempts to revoke provider access |

Example arguments for `generate_text`. Replace the model value with an ID from `list_models`.

```json
{
  "model": "MODEL_ID_FROM_LIST_MODELS",
  "prompt": "Summarize OAuth PKCE in two sentences.",
  "max_output_tokens": 1024
}
```

`max_output_tokens` is optional. It defaults to 256 and accepts values from 1 to 4096.

## Cookies and account data

- The Worker reads two cookies it creates on its own domain. `__Host-antigravity` lasts 10 minutes and `__Host-google-oauth` lasts 5 minutes. Both carry a hash of the OAuth state and use `Secure`, `HttpOnly`, and `SameSite=Lax`.
- The Worker uses those cookies to validate the sign-in callback. It does not access browser cookie storage or forward the incoming cookie header to Google or Antigravity.
- The Worker stores OAuth credentials encrypted in D1. Status responses can show the signed-in user's connected Google profile. The model and prompt go to Antigravity when generation is requested.

## Development

Use Node.js 22 or later, Python 3, and Bash. On Windows, run the build from Git Bash.

```sh
npm test
npm run build
npm run validate
```

The tests use simulated provider responses and an in-memory SQLite database. They cover OAuth state and PKCE, account isolation, token refresh and revocation, model discovery, and text generation.
