---
version: 1
---

# Team Google Drive MCP on Cloud Run

**Started:** 2026-04-15
**Status:** Draft

## Summary

Deploy a team-wide Google Drive MCP server on Cloud Run in `rs-workspace-integrations`, exposed to claude.ai as a custom connector. Uses per-user OAuth (each team member acts as themselves against Google Drive) with refresh tokens stored in Firestore, envelope-encrypted via Cloud KMS. Starts from a fork of `piotr-agier/google-drive-mcp` which already supports Streamable HTTP transport; layers on per-user OAuth, Firestore-backed token storage, and an internal-only Google OAuth consent screen.

Unlocks the `relevant-brand-guidelines` skill's `createDocFromHTML` path (uncommitted upstream change) so branded docs can be generated directly in users' Drives.

## Documents

- [Design](./2026-04-15-drive-mcp-team-design.md)
- [Plan 1 — Infrastructure (rs_infra)](./2026-04-15-drive-mcp-team-plan-1-infra.md) — execute first
- [Plan 2 — App (fork + OAuth server + deploy)](./2026-04-15-drive-mcp-team-plan-2-app.md) — execute after Plan 1 is merged
