---
version: 1
---

# Design: Drive MCP refresh-token support

**Project:** [Drive MCP refresh-token support](./index.md)
**Status:** Draft
**Repo:** `RelevantSearch/google-drive-mcp` (fork, default branch `master`)
**Live service:** `drive-mcp` in `rs-workspace-integrations`, exposed at `https://drive-mcp.relevantsearch.com/mcp`

## Problem

Users of the team Drive MCP connector are forced to reconnect via `Settings > Connectors` every 2-3 days. Initial diagnosis attributed the cycle to Google OAuth verification or scope-expiry policy. Source-level investigation falsified that theory.

In `src/auth/provider.ts` on the fork's `master` branch:

```ts
expires_in: 3600,        // 1-hour AS-hop JWT
...
async exchangeRefreshToken(...) {
  throw new Error('Refresh tokens not supported');
}
```

The AS hop (claude.ai to our MCP server) issues a 1-hour bearer JWT and explicitly does not honor refresh-token grants. Every 60 minutes claude.ai must redo the full OAuth flow against our `/authorize` endpoint, which redirects to Google. While the user's Workspace SSO cookie is alive, that redirect chain completes silently. Once the cookie lapses (~2-3 days under default Workspace policy), the user sees the connector as disconnected and reconnects manually.

The OAuth consent screen is already configured as Internal in `rs-workspace-integrations`, so the Google IdP hop is not the limiting factor. The bottleneck is in our own AS hop.

## Goal

Honor RFC 6749 / OAuth 2.1 refresh-token semantics in the AS hop so that claude.ai can extend its session against our server without redoing the Google flow. Eliminate the 2-3 day relogin cycle. Forced re-auth still happens at the 90-day chain TTL as a security checkpoint.

## Non-goals

- No change to the Google IdP hop (existing per-user Google OAuth flow stays as-is).
- No change to the Cloud Run / Firestore / KMS infrastructure in `rs-workspace-integrations`.
- No change to OAuth scopes or consent screen.
- No new external dependencies.
- No verification submission or External-mode support (Internal stays).

## Architecture

The two-hop OAuth shape is unchanged:

```
claude.ai  <-- AS hop -->  drive-mcp server  <-- IdP hop -->  Google
```

A new refresh-token store backs the AS hop. The existing per-user Google credentials store (Firestore `user_tokens/{userId}`) is untouched - it already holds the long-lived Google refresh_token. Google access-token refresh is already handled lazily by `getUserAccessToken` in `src/auth/user-token.ts` (called on every tool invocation), so the AS-hop refresh flow does not need to call Google directly.

```
+----------------------------+
| AS-hop refresh tokens      |  <-- NEW: refresh_tokens collection
| (Firestore, hashed)        |
+----------------------------+
              ^
              |  validate / rotate / revoke
              |
+----------------------------+
| DriveOAuthProvider         |  <-- modified: exchangeRefreshToken impl
| (provider.ts)              |
+----------------------------+

(Google access_token refresh stays in user-token.ts on the tool-call path,
unchanged by this design.)
```

## Components

### `src/auth/refresh-token-store.ts` (new)

Firestore-backed store. Raw tokens are 32-byte cryptographically random values (`crypto.randomBytes(32).toString('base64url')`). Raw tokens are returned to the client once and never persisted; Firestore stores the SHA-256 hash as the document ID.

Public surface:

| Method | Returns | Notes |
|---|---|---|
| `issue(userId, email, scopes) -> {rawToken, chainId, expiresAt}` | new chain head | New `chainId` UUID, `expiresAt = now + 90d` |
| `rotate(rawToken) -> {rawToken, chainId, expiresAt}` | new chain link | Atomic: marks old `rotated`, writes new `active` with same chainId and expiresAt |
| `validate(rawToken) -> RefreshTokenRecord` | doc state | Hashes input, reads doc, returns status |
| `revokeChain(chainId) -> void` | | Marks all docs in chain `revoked` |
| `revokeUser(userId) -> void` | | Marks all docs for user `revoked` (used by `revokeToken` if revoking by access token) |

Atomicity: rotation is a Firestore transaction over two documents (old chain link + new chain link).

### `src/auth/provider.ts` (modified)

| Method | Change |
|---|---|
| `exchangeAuthorizationCode` | Also call `refreshTokenStore.issue(...)`, include `refresh_token` in returned `OAuthTokens` |
| `exchangeRefreshToken` | Replace stub. Validate, rotate, mint new JWT, return new pair. See data flow. |
| `revokeToken` | Implement: look up token (refresh or access), call `refreshTokenStore.revokeChain` |

### `src/auth/google-oauth.ts` (unchanged)

`GoogleOAuth.refreshAccessToken(refreshToken)` already exists and is called by `getUserAccessToken` in `user-token.ts` on the tool-call path. No changes here.

### `src/auth/jwt.ts` (unchanged)

JWT TTL stays at 3600s. The refresh flow is what extends the session, not the JWT itself.

## Data model

New Firestore collection `refresh_tokens`:

| Field | Type | Notes |
|---|---|---|
| `docId` (implicit) | string | SHA-256(rawToken), base64url-encoded |
| `userId` | string | foreign key to `users` |
| `email` | string | denormalized for logging |
| `scopes` | string[] | scope set granted with this token |
| `chainId` | string | UUIDv4, shared across all rotations of the same logical session |
| `createdAt` | Timestamp | when this specific link was issued |
| `expiresAt` | Timestamp | chain TTL, NOT per-link. Inherited by rotations. |
| `status` | enum | `active` \| `rotated` \| `revoked` |
| `rotatedAt` | Timestamp \| null | when this link was superseded |

Indexes:

- Composite on `(chainId, status)` for chain-revoke
- Single on `userId` for diagnostic / admin tools

TTL semantics: `expiresAt` is set once at chain creation (`issue`) and copied verbatim to every rotated successor. This ensures the 90-day forced re-auth lands on schedule regardless of how often the chain rotates.

## Data flow

### Initial authorization (existing flow plus refresh_token issuance)

1. claude.ai redirects user to `/authorize`
2. Server redirects user through Google OAuth, captures Google tokens, stores them in `users/{userId}/credentials`
3. Server stores authorization code in `auth_codes` collection
4. claude.ai POSTs to `/token` with `grant_type=authorization_code`
5. SDK calls `exchangeAuthorizationCode`
6. Provider consumes the auth code, **issues a refresh_token via `refreshTokenStore.issue`**, mints JWT
7. Returns `{access_token, refresh_token, token_type: 'bearer', expires_in: 3600, scope}`

### Refresh (new)

1. claude.ai POSTs to `/token` with `grant_type=refresh_token`, `refresh_token=<raw>`, `client_id`, `client_secret`
2. SDK validates client (existing plaintext compare), calls `exchangeRefreshToken(client, rawToken)`
3. `refreshTokenStore.validate(rawToken)` reads `refresh_tokens/<sha256(raw)>`
4. Branch on state:

| State | Action |
|---|---|
| not found | return `invalid_grant` |
| `status=revoked` | return `invalid_grant` |
| `expiresAt < now` | mark `revoked`, return `invalid_grant` |
| `status=rotated`, within 5s grace window | return identical pair as last rotation (idempotent retry) |
| `status=rotated`, beyond grace window | reuse detected: `revokeChain(chainId)`, return `invalid_grant` |
| `status=active` | proceed |

5. Atomic transaction: update old doc to `status=rotated, rotatedAt=now`, write new doc with same `chainId`, same `expiresAt`, fresh raw token, `status=active`
6. Cache the (rawToken, newPair) tuple in-memory for 5s to support the idempotent-retry grace window
7. Mint new JWT (`jwt.sign({sub: userId, email, scope})`)
8. Return `{access_token: jwt, refresh_token: newRaw, token_type: 'bearer', expires_in: 3600, scope}`

The AS-hop refresh does NOT call Google. The next tool call invokes `getUserAccessToken`, which lazily refreshes the Google access_token from the stored refresh_token via the existing path in `user-token.ts`. If Google has revoked the user's grant, that path throws `InvalidGrantError`, which surfaces as a 401 to claude.ai and triggers reconnect. This keeps the AS hop fast and decoupled from Google's availability.

### Revoke (new)

1. claude.ai POSTs to `/revoke` with `token=<raw>`
2. Provider attempts to look up as refresh_token (hash match in `refresh_tokens`); if found, `revokeChain(chainId)`
3. If not found, attempt as access_token: verify JWT signature, extract `sub`, call `revokeUser(userId)` to revoke all chains for that user
4. Return `200 OK` regardless of whether token existed (RFC 7009 compliance)

## Error handling

| Condition | Response | Side effect |
|---|---|---|
| Unknown / revoked / expired refresh_token | `400 invalid_grant` | none |
| Reuse detected (rotated token presented beyond 5s grace) | `400 invalid_grant` | revoke entire chain |
| Idempotent retry within 5s grace | `200 OK` | return same new pair |
| Firestore transient error during validate / rotate | `503 temporarily_unavailable` | none, retain current chain |
| Google revocation (detected on subsequent tool call, not here) | tool call returns `401`, claude.ai prompts reconnect | handled by existing `user-token.ts` path |
| Scope reduction requested in refresh | honor it | new token is narrower-scoped |
| Scope escalation requested in refresh | `400 invalid_scope` | none |

### Notes on tricky cases

**5-second idempotent-retry grace window** (RFC 6819 advice). claude.ai may retry a refresh on transient network failure with the same raw token. Without grace, the second call sees `status=rotated` and triggers a chain revoke - false positive. The window is implemented as an in-memory cache keyed by hash(rawToken), value being the most recent (newPair, chainId), evicted after 5s. Outside the grace window, `status=rotated` always means leak.

**Decoupling from Google availability**. By design, the AS hop never calls Google during refresh. This means our refresh is fast (Firestore-only) and resilient to Google outages. The trade-off: if a user revokes our app at myaccount.google.com, claude.ai's next AS-refresh will succeed but the subsequent tool call will fail with 401 (since `getUserAccessToken` will hit `InvalidGrantError` from Google). claude.ai surfaces the 401 and prompts reconnect. Worst-case latency to detection: one tool-call round-trip after revocation, generally seconds.

## Migration

No DB migration. The new `refresh_tokens` collection is created on first write. On deploy:

1. Existing 1-hour JWTs continue working until their natural expiry (within 1 hour).
2. When claude.ai's next request fails on expired JWT, the connector re-runs `/authorize` against the new code and receives a refresh_token in the response.
3. From the next refresh onward the user is on the new flow with no relogin until the 90-day chain TTL.

Worst case for an individual user: one final relogin within an hour of deploy. No coordinated migration window or announce-and-cutover required.

## Testing

Run baseline test suite on `master` first per `feedback_baseline_tests_before_changes`; document any pre-existing failures before adding tests.

| Test | Where | Coverage |
|---|---|---|
| Unit: hashing, rotation, chain revoke, reuse detection, expiry, grace window | `test/auth/refresh-token-store.test.ts` (new) | Storage layer in isolation, mock Firestore via emulator or in-memory shim |
| Integration: full refresh round-trip | `test/integration/refresh-flow.test.ts` (new) | Issue → refresh → rotate → re-refresh, no Google call expected |
| Integration: reuse detection | same file | Present rotated token beyond grace, expect `invalid_grant` + chain revoked |
| Integration: grace window | same file | Same raw token presented twice within 5s returns identical pair, no revoke |
| Integration: revokeToken endpoint | extend `oauth-provider.test.ts` | Token revoke invalidates the chain; subsequent refresh fails |
| E2E: refresh in full claude.ai-style flow | extend `e2e-oauth-flow.test.ts` | Authorize → token (with refresh) → refresh → access protected resource |

Per `feedback_iterate_locally_not_ci`: integration tests run locally before each push.

## Deploy

CI workflow `.github/workflows/deploy.yml` already deploys `master` to the `drive-mcp` Cloud Run service in `rs-workspace-integrations` via WIF (`drive-mcp-deployer` SA). Single PR → merge → auto-deploy. No staging environment.

Verification plan post-deploy:

1. Smoke: reconnect in claude.ai, make a Drive call, confirm it works.
2. Wait at least 1 hour, make another Drive call, confirm no re-prompt (proves refresh worked end-to-end).
3. Inspect Firestore `refresh_tokens` collection: expect `rotated` and `active` docs sharing a `chainId`.
4. Watch Cloud Run logs for `invalid_grant` spikes that would signal a bug in reuse detection or the grace window.

## Rollback

Single-commit revert on `master`, CI redeploys the previous image. Orphaned `refresh_tokens` documents remain but cause no harm: validated against the old (stub-throw) code path, they fail and force a fresh `/authorize`. Optional cleanup: a one-shot script to mark all `refresh_tokens` documents `revoked` after rollback, but not required.

## Open questions

None. Section reserved for items that surface during implementation.

## References

- RFC 6749 - The OAuth 2.0 Authorization Framework
- RFC 6819 - OAuth 2.0 Threat Model and Security Considerations (grace window for retry)
- RFC 7009 - OAuth 2.0 Token Revocation
- OAuth 2.1 draft - rotation requirement for public clients
- Predecessor design: [2026-04-15 drive-mcp-team-design](../2026-04-15-drive-mcp-team/2026-04-15-drive-mcp-team-design.md)

## Changelog

### v1 - 2026-05-02

Initial design.
