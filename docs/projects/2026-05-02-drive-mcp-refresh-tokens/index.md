---
version: 1
---

# Drive MCP refresh-token support

**Started:** 2026-05-02
**Status:** Draft

## Summary

Eliminate the 2-3 day forced relogin cycle on the team Drive MCP connector at `drive-mcp.relevantsearch.com` by implementing OAuth 2.1 refresh-token support in the AS hop. The current implementation issues a 1-hour JWT and explicitly throws on `exchangeRefreshToken`, forcing claude.ai to redo the full OAuth flow whenever the JWT expires. The flow is silent for ~2-3 days while Google's session cookie keeps the redirect transparent, then surfaces as a "Drive isn't connected" prompt when the Workspace SSO session lapses.

Fix: implement `exchangeRefreshToken` in `DriveOAuthProvider`, back it with a Firestore `refresh_tokens` collection of opaque rotated tokens (90-day chain TTL, reuse detection, revoke endpoint). Existing per-user Google refresh_tokens in Firestore are reused for the upstream Google refresh call, no new Google scope or consent change required.

This is a single-PR change in this repo. No infra changes.

## Documents

- [Design](./2026-05-02-drive-mcp-refresh-tokens-design.md)
- [Implementation Plan](./2026-05-02-drive-mcp-refresh-tokens-plan.md)

## Canonical location

These docs are mirrored from `rs_infra/docs/projects/2026-05-02-drive-mcp-refresh-tokens/`. Edits should originate in rs_infra and propagate here.
