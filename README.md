# Cosmos API Platform

A Node.js API dashboard backed by SQLite. The application includes account registration and login, optional email verification, API-key creation and revocation, two public model IDs, a request playground, usage history, and an OpenAI-compatible chat-completions endpoint.

## Requirements

- Node.js 22 or newer
- A compatible OpenAI-style chat-completions endpoint for Cosmos Photon 3
- A server-side model API key for Cosmos Blazar 3
- SMTP settings if email verification is enabled

## Install and run

```bash
npm install
```

Copy `.env.example` to `.env` and set a private `SESSION_SECRET`. Verify `PHOTON_API_BASE_URL` points to the chat-completions service reachable from the Node.js server. Set `GEMINI_API_KEY` for Cosmos Blazar 3 and verify `GEMINI_MODEL` is enabled for that API key. The example model setting is `gemma-4-31b-it`; it is configurable and is never sent to clients. For local Photon development, the example uses `http://127.0.0.1:9655/v1`.

```bash
npm start
```

Open `http://localhost:4000`.

For a local development account, `EMAIL_VERIFICATION_REQUIRED=false` permits registration without email verification. Before public deployment, set `NODE_ENV=production`, use a randomly generated session secret of at least 32 characters, enable email verification, configure SMTP, and terminate TLS at a trusted HTTPS reverse proxy.

## Appearance

The interface includes a theme control on both the sign-in/register screen and the developer workspace. The selected light or dark theme is saved in the browser and restored on the next visit. The supplied Cosmos logo is converted to a transparent PNG and used in the branding and favicon assets.

## Model routing

The public model IDs are `cosmos-photon-3` and `cosmos-blazar-3`. Both are served through the same backend endpoint, `POST /v1/chat/completions`, using a Cosmos API key. The browser never calls a model provider directly.

Cosmos Photon 3 forwards requests to the private OpenAI-style endpoint configured through `PHOTON_API_BASE_URL`; the backend supplies `PHOTON_UPSTREAM_MODEL` and clients cannot override the upstream model. Successful JSON and streaming responses are normalized to the public Cosmos model ID.

Cosmos Blazar 3 is handled by a server-side adapter using `GEMINI_API_KEY`, `GEMINI_API_BASE_URL`, and `GEMINI_MODEL`. The adapter converts OpenAI-style messages to the model API's request structure and returns a compatible response or server-sent events. Provider-specific errors are replaced with generic client-safe messages.

### Blazar 3 daily token allowance

Cosmos Blazar 3 has a hard allowance of **10,000 input and output tokens per account per UTC day**. All API keys owned by the same user share the limit, and requests submitted through the Playground count toward the same allowance. The server calls the model's token-counting endpoint before generation, reserves the requested output ceiling atomically in SQLite to prevent concurrent requests from overspending, then settles the reservation against the reported total token usage, including hidden reasoning tokens where reported. If a generation begins but usage telemetry is missing, it settles conservatively against the reserved output ceiling. The counter resets at 00:00 UTC.

If `GEMINI_API_KEY` is absent or the configured model cannot be reached, Blazar 3 returns a generic availability error; it does not silently fall back to Photon 3. This is intentionally independent from Photon 3's upstream configuration.

Keep `PHOTON_API_KEY`, `GEMINI_API_KEY`, SMTP credentials, and all secrets in server-side environment configuration. No provider key or endpoint is embedded in browser code or returned through public API responses.

## Model discovery

List the model identifiers available to a key:

```bash
curl "http://localhost:4000/v1/models" -H "Authorization: Bearer YOUR_COSMOS_API_KEY"
```

## API keys

Create keys from the **API keys** page. The full key is only returned once and only its SHA-256 hash is stored in SQLite. If a key is lost, revoke it and create another one.

Example:

```bash
curl "http://localhost:4000/v1/chat/completions" \
  -H "Authorization: Bearer YOUR_COSMOS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "cosmos-photon-3",
    "messages": [{"role": "user", "content": "Hello, Cosmos."}],
    "stream": false
  }'
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP listening port |
| `SESSION_SECRET` | Session signing secret; required to be strong in production |
| `DATA_DIR` | Location for SQLite data and session database |
| `DATABASE_PATH` | Main SQLite database path |
| `PHOTON_API_BASE_URL` | Private model endpoint base URL, accessible only from the backend |
| `PHOTON_API_KEY` | Optional credential for the private model endpoint |
| `PHOTON_UPSTREAM_MODEL` | Internal model value sent only by the backend |
| `PHOTON_REQUEST_TIMEOUT_MS` | Upstream request timeout for model calls |
| `PHOTON_MAX_CONCURRENT_REQUESTS` | Server-side concurrency ceiling shared across model calls |
| `GEMINI_API_BASE_URL` | Base URL for the Blazar server-side API adapter |
| `GEMINI_API_KEY` | Server-only credential required for Blazar 3 |
| `GEMINI_MODEL` | Backend model identifier used by the Blazar adapter |
| `API_USER_REQUESTS_PER_MINUTE` | Base per-account request rate; effective throughput is reduced at high concurrency |
| `EMAIL_VERIFICATION_REQUIRED` | Enables email code verification |
| `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_SECURE`, `EMAIL_USER`, `EMAIL_PASSWORD`, `EMAIL_FROM` | SMTP settings used when verification is enabled |

## Security notes

- This is a deployable starting implementation, not a claim of having passed an independent security audit.
- Use HTTPS in production and set `TRUST_PROXY` only to the correct trusted proxy count.
- Back up the SQLite database and session database securely. Use encrypted storage and restrictive filesystem permissions.
- Do not serve `.env`, the `data` directory, source maps, or database files as static assets.
- If using this for a public service with significant traffic, consider SQLite write/concurrency limits and the operational requirements of your hosting environment before launch.
- The browser UI does not show private provider identifiers or server-side model settings. Technical configuration still needs to be documented for operators and kept out of public responses.

## Tests and checks

```bash
npm run check
npm test
```

The automated tests cover health, registration, API key issuance and revocation, key-hash storage, session protection, model discovery, request validation, and concurrent Blazar token-budget reservations. They deliberately do not require the real model server or generate billable model traffic.
