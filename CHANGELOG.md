# 0.3.7

- Fix 3x-ui generated REALITY QR/share links with empty `pbk=`.
- Store `realitySettings.settings.publicKey/fingerprint/serverName/spiderX` on generated inbounds.
- Verify the panel persisted REALITY share metadata after add/update.
- Keep dual entry (XHTTP + TCP/RAW) and per-server port reuse from 0.3.5.

# 0.3.6

- Fix REALITY client compatibility with current Xray: emit non-empty `password` as well as legacy `publicKey`.
- Fix immutable-receiver reuse to populate both REALITY key field names.
- Prevent generated modern client profiles from failing with `REALITY config: empty 'password'`.

# 0.3.5

- Port allocation is explicitly per-server; the same numeric port can be reused on different VPS hosts.
- Re-deploy prefers the existing cascade receiver port before allocating a new port, avoiding false pool exhaustion/collisions.
- Dual client entry is enabled by default: VLESS+REALITY+XHTTP plus VLESS+REALITY+TCP/RAW on separate ports of the entry server.
- Both entry inbounds route into the same cascade outbound; generated output contains both share links and client profiles.
- If an old 3x-ui can list an existing VLESS+REALITY inbound but update returns HTTP 500, deploy can reuse that inbound as an immutable receiver and adapt the predecessor/client to its live credentials.

# 0.3.3

- Treat 3x-ui inbound delete as postcondition-based: HTTP 500 is tolerated if the inbound actually disappeared.
- Retry delete using bodyless, form and JSON request variants for old/new panels.
- Make redeploy/rollback deletion idempotent and verify via `/panel/api/inbounds/list`.

# Changelog

## 0.3.2

- Fixed 3x-ui inbound deployment compatibility after HTTP 500 from `/panel/api/inbounds/add`.
- Inbound creation now tries compact JSON, `/panel/api/inbounds/import`, tagged JSON, then legacy form data.
- Lets 3x-ui choose its native inbound tag when supported and rewrites routing to the tag actually returned by the panel.
- Uses a conservative cross-version inbound payload and keeps newer bookkeeping fields out of the first compatibility attempt.
- Uses unique simple client identifiers/subIds for panel-created VLESS clients.
- Cascade ownership is also tracked by remark, so removal/redeploy works when a panel generates its own inbound tag.
- Writes attempted inbound payloads, responses and errors to `deploy-debug/` for real panel diagnostics.

## 0.3.0

- Added direct 3x-ui deployment.
- Added Bearer token authentication for newer panels.
- Added legacy `/login` username/password session-cookie authentication.
- Added CSRF support when a newer panel requires it for cookie-authenticated writes.
- Auto-detects `/panel/api/xray` and legacy `/panel/xray` Xray Settings endpoints.
- Added panel connection tester to ncurses and CLI.
- Added deploy/remove operations with cascade-specific tags.
- Added pre-deploy snapshots and best-effort rollback.
- Added port conflict avoidance using existing panel inbounds.
- Added assembled runtime verification where supported.
- XHTTP + REALITY is now the default transport; TCP remains available.
- Generated topology copies redact panel credentials.

## 0.2.0

- Added ncurses SNI management and validation.
- Added `check-sni` CLI and SNI reports.
