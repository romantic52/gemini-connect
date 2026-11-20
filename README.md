# Gemini Connect

Gemini Connect is an unofficial MCP server that sends text prompts to models available through a connected Antigravity account. It can list model IDs, report quota information returned by the provider, check account status, and test generation separately from Google sign-in.

## Run the checks

Use Node.js 22 or later, Python 3, and Bash for the build.

```sh
npm test
npm run build
npm run validate
```

The tests use simulated Google and Antigravity responses and a real in-memory SQLite database. They cover account isolation, OAuth state and PKCE, disconnect and refresh, model discovery, and text generation.

## Configure a deployment

The server targets an authenticated OpenAI Sites Worker environment with a D1 database. The hosting manifest and migrations are included. The Worker trusts identity headers supplied by Sites. If adapting it to another host, put it behind an authentication layer that strips caller-supplied values for those headers and injects a verified identity. Restrict access to the Worker through that layer.

1. Bind a D1 database as `DB` and apply the migration in `drizzle/`.
2. Set `SITE_ORIGIN` to the deployment's exact HTTPS origin, without a trailing slash.
3. Set `TOKEN_ENCRYPTION_KEY` as a runtime secret. Generate a fresh 32-byte base64url key per deployment with `node -p "require('node:crypto').randomBytes(32).toString('base64url')"`.
4. Set `ANTIGRAVITY_CLIENT_ID` and `ANTIGRAVITY_CLIENT_SECRET` as runtime secrets for the OAuth client configuration used by the integration. See the [protocol reference](THIRD_PARTY_LICENSES.md). Keep credentials out of version control.
5. Run the build and deploy the contents of `dist/` with your hosting platform's project configuration. Register your own authenticated `/mcp` endpoint with your MCP client.
6. Open `/antigravity` while signed in to the deployment. Complete Google consent and enter the loopback return URL in the protected form. Keep that URL out of chat, logs, and issue reports.

The separate Google profile-only flow uses a Web OAuth client with the deployment's `/oauth/callback` redirect URI. It does not grant model access.

## Use the MCP tools

- `account_status` reports the Google connection and checks provider access.
- `list_models` returns the exact model IDs the provider exposes to the connected account. `usage_limits` reports the quota values the provider supplies.
- `generate_text` takes a model ID and prompt. Its optional `max_output_tokens` accepts 1–4096 tokens and defaults to 256.
- `test_request` checks actual generation on an available model. `disconnect` removes the stored connection and attempts to revoke provider access.

Model access depends on the account and the provider. The Antigravity adapter uses an unofficial protocol. The existing hosted plugin and its credentials are private. This repository distributes the server source.
