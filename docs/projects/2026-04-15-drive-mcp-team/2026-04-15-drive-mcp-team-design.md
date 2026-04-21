---
version: 1
---

# Design: Team Google Drive MCP on Cloud Run

**Date:** 2026-04-15
**Status:** Draft
**Parent:** [index.md](./index.md)

## Goal

Expose a shared Google Drive MCP server to the Relevant Search team via claude.ai's Custom Connectors. Each user authenticates once with their `@relevantsearch.com` Google identity; the server acts on that user's Drive for all subsequent tool calls. Unlocks HTML-based branded document generation from claude.ai.

## Non-goals

- External (non-Workspace) users
- Public/external Google OAuth verification
- Production-tier environment in v1 (nonprod only)
- Cloud Armor / geo restrictions in v1
- Proactive Admin SDK token purge (rely on Google's automatic revocation on account suspend/delete)

## Background

The upstream repo `piotr-agier/google-drive-mcp` already ships:

- Streamable HTTP transport (commit `f9aa097`)
- Service-account and external-OAuth-token auth modes (commit `395ef05`)
- 40+ Drive/Docs/Sheets/Slides tools

We have an uncommitted local change adding a `createDocFromHTML` tool (~80 LOC in `src/tools/docs.ts`) that uses Drive API MIME conversion to avoid the paragraph-style inheritance bug — critical for the `relevant-brand-guidelines` skill.

What the upstream does **not** ship: a full MCP-spec OAuth 2.1 authorization server that lets claude.ai register dynamically and authenticate multiple end users. That's the primary build in this project.

## Architecture

```
+-------------+       OAuth 2.1        +------------------+       OAuth 2.0       +--------+
|  claude.ai  | <--------------------> |  MCP server       | <-------------------> | Google |
|  connector  |    (we issue tokens)   |  (Cloud Run)      |  (user consent flow)  | Drive  |
+-------------+                        +------------------+                       +--------+
                                              |
                                              v
                                        +-----------------+
                                        | Firestore        |
                                        | - oauth_clients  |
                                        | - user_tokens    |
                                        |   (KMS-wrapped)  |
                                        +-----------------+
```

### Components

**App (fork of `piotr-agier/google-drive-mcp` → `relevantsearch/google-drive-mcp`)**

New surface added in the fork:

- `/.well-known/oauth-authorization-server` — MCP-spec discovery metadata
- `/register` — RFC 7591 dynamic client registration (claude.ai auto-registers on first add)
- `/authorize` — starts Google OAuth flow, stores `state` in Firestore
- `/oauth/google/callback` — receives Google code, exchanges for tokens, stores in Firestore
- `/token` — issues our short-lived JWT access tokens to claude.ai
- `/mcp` — Streamable HTTP MCP endpoint (existing, now gated on our JWT)

All existing MCP tools continue to work; each tool handler resolves the Google refresh token from Firestore via the JWT's `sub` claim and uses it to call Drive.

**Infrastructure (rs_infra Terragrunt module `workspace-integrations-mcp`)**

Target project: `rs-workspace-integrations` (nonprod only in v1).

- Cloud Run service `drive-mcp` (min instances 1, max 10, 512MB, concurrency 20) — CMEK-encrypted
- Artifact Registry repo `drive-mcp`
- Firestore (Native mode) — CMEK via dedicated Cloud KMS key
- Cloud KMS keys in `kms-proj-a9dncstlc3zg`:
  - `drive-mcp-cloud_run` — Cloud Run CMEK
  - `drive-mcp-firestore` — Firestore CMEK
  - `drive-mcp-secrets` — Secret Manager CMEK
  - `drive-mcp-token` — app-level envelope encryption of user refresh tokens
- Service account `drive-mcp@rs-workspace-integrations.iam.gserviceaccount.com` with `datastore.user`, `cloudkms.cryptoKeyEncrypterDecrypter` (on `drive-mcp-token` only), `logging.logWriter`
- Secret Manager secrets: `drive-mcp-google-oauth-client-id`, `drive-mcp-google-oauth-client-secret`, `drive-mcp-mcp-signing-key` (sourced via SOPS per ADR-010)
- Serverless NEG → Cloud Run (not Internet NEG — known gotcha from success-dna LB investigation)
- External HTTPS Load Balancer + Google Compute managed SSL certificate (`google_compute_managed_ssl_certificate`) for `drive-mcp.relevantsearch.com`
- DNS A record points to LB IP — this is how the managed cert validates; no separate Certificate Manager DNS authorization CNAME is needed
- No IAP (conflicts with the MCP server's own OAuth)

### Data model (Firestore)

`oauth_clients/{client_id}`

```
{
  client_id: string,           // generated, returned to claude.ai on /register
  client_secret_hash: string,  // SHA-256
  redirect_uris: string[],
  created_at: timestamp,
  last_used_at: timestamp
}
```

`user_tokens/{google_subject}`

```
{
  google_subject: string,       // Google's `sub` — immutable user ID
  email: string,                // @relevantsearch.com
  refresh_token_ciphertext: bytes,  // KMS envelope-encrypted Google refresh token
  kms_key_version: string,          // for rotation support
  scopes: string[],
  created_at: timestamp,
  last_refreshed_at: timestamp
}
```

No plaintext tokens are ever stored. Even a Firestore read bypass can't produce usable Google credentials without `cloudkms.cryptoKeyDecrypter` on `drive-mcp-token`.

## Security & compliance

**Identity:**

- Google OAuth consent screen type = **Internal** → only `@relevantsearch.com` accounts can authenticate; no Google verification required.
- Scopes: `drive`, `documents`, `spreadsheets`, `presentations` (full Drive, matching upstream tool surface).
- MCP-issued JWTs: HS256, 1-hour TTL, signed with `drive-mcp-mcp-signing-key` (rotated every 90 days).

**Token revocation:**

- When Google Workspace admin suspends/deletes a user, Google auto-revokes their OAuth tokens within minutes.
- Our refresh attempt returns `invalid_grant` → we delete the `user_tokens/{subject}` doc and force re-auth (which fails because the account is gone).
- No proactive polling needed in v1.

**Encryption:**

- All services use CMEK per org policy `constraints/gcp.restrictNonCmekServices`.
- User refresh tokens have a second layer of encryption (application-level envelope via `drive-mcp-token`) — Firestore read access alone does not yield plaintext.

**Network:**

- HTTPS-only via managed cert.
- No IAP (MCP does its own OAuth).
- No geo restrictions in v1 (deferred).

## Lessons applied from prior rs_infra incidents

| Incident | Lesson | Applied how |
|---|---|---|
| PR #82 / #85 — Cloud Run create failed | CMEK mandatory per org policy | Dedicated KMS keys per service, bindings created before service resources |
| PR #89 — Firestore apply transient failure | IAM binding eventual consistency | Explicit `depends_on` on `google_firestore_database` pointing at the IAM binding |
| success-dna #44 — LB 403 on `/api/**` | Need serverless NEG, not Internet NEG | Module uses `google_compute_region_network_endpoint_group` with `cloud_run` target |
| PR #90 — Wildcard cert stuck in FAILED | DNS authorization CNAME not created | N/A — this module uses `google_compute_managed_ssl_certificate` (validated via the LB's A record), not Certificate Manager, so no DNS authorization CNAME is required |
| google_iap_brand/client deprecation (2026-03-19) | Can't auto-create OAuth clients | Google OAuth client created manually in Cloud Console, credentials stored in SOPS |
| ADR-007 | Terragrunt per-component state isolation | New module lives at `environments/non-production/workspace-integrations/drive-mcp/` |
| ADR-010 | SOPS + Secret Manager for secrets | `*.enc.yaml` for OAuth client + signing key, provisioned via `carlpett/sops` provider |

## CI/CD

**App repo (`relevantsearch/google-drive-mcp`):**

- GitHub Actions, triggered on push to `main` and semver tags
- Steps: lint → unit tests → integration tests (mock Google OAuth server) → Docker build → push to Artifact Registry via Workload Identity Federation → `gcloud run deploy`
- No manual deploys

**Infra repo (`rs_infra`):**

- Standard Terragrunt `plan`/`apply` pipeline per ADR-007
- First apply is manual (bootstraps KMS keys + state); subsequent changes via CI

## Testing strategy

**App unit tests (add to fork):**

- `createDocFromHTML`: happy path, duplicate-name conflict, missing folder, invalid HTML
- OAuth authorization server handlers: `/register`, `/authorize`, `/token` — all happy + error paths
- Token envelope encryption: encrypt → store → fetch → decrypt round trip
- `invalid_grant` handling: Firestore doc purged, user forced to re-auth

**Infra tests:**

- `tofu plan` clean in CI before merge
- Post-apply smoke: `gcloud kms keys get-iam-policy` verifies all service identity bindings
- `curl https://drive-mcp.relevantsearch.com/.well-known/oauth-authorization-server` returns valid JSON

**End-to-end (manual for v1):**

- Stefan registers the connector in claude.ai, completes Google OAuth flow
- Calls `createDocFromHTML` with a branded doc — verifies output in Drive
- Admin suspends a test user — verifies next MCP call returns 401 and Firestore doc is purged

## Observability

- **Structured logs** (Cloud Logging): `user_subject`, `tool_name`, `latency_ms`, `error_code`. Never log HTML bodies or tokens.
- **Alerts** (Cloud Monitoring → Slack):
  - 5xx rate > 1% over 5min
  - `invalid_grant` rate > 3/min (possible mass revocation / incident)
  - Cloud Run cold-start ratio > 10% (tune min-instances)
- **SLO:** 99.5% availability (internal tooling; not customer-facing)

## Rollout plan

| Phase | Owner | Gate |
|---|---|---|
| 1. Infra (rs_infra PR) | Platform | `tofu plan` clean, manual first apply, smoke curl |
| 2. Google OAuth consent screen + client | Workspace admin | Credentials in SOPS |
| 3. App fork + `createDocFromHTML` commit + deploy | Platform | CI green, Cloud Run serves `/.well-known/...` |
| 4. Stefan-only connector test in claude.ai | Stefan | E2E `createDocFromHTML` works |
| 5. 2–3 early testers enabled | Stefan | No issues for 48h |
| 6. Org-wide enablement | Stefan | Short onboarding doc posted in Slack |

## Open questions

None at design time. First implementation-plan-level decisions (module file layout, precise IAM bindings, JWT library choice) will be made during plan writing.

## Related

- ADR-003 — CMEK / Autokey encryption
- ADR-007 — Terragrunt state management
- ADR-008 — Workload Identity Federation
- ADR-010 — SOPS secrets management
- `docs/projects/2026-03-26-preview-environments/` — preview infra post-mortems (PRs #82, #85, #89, #90)
- `modules/firebase-hosting/main.tf` — reference implementation for Cloud Run + LB + CMEK + serverless NEG
