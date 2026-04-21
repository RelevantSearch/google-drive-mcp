# Drive MCP — team connector setup

This guide is for Relevant Search team members who want to connect their claude.ai account to our hosted Drive MCP server. One-time setup, takes about a minute.

**Prerequisites:** a `@relevantsearch.com` Google account. The server rejects every other domain — there is no bypass.

## 1. Open claude.ai and add the connector

1. Sign into [claude.ai](https://claude.ai) with any account.
2. Open **Settings → Connectors**.
3. Click **Add custom connector**.
4. Enter:
   - **Name:** `Relevant Search Drive`
   - **URL:** `https://drive-mcp.relevantsearch.com/mcp`
5. Click **Add**.

## 2. Sign in with Google

claude.ai redirects you to a sign-in screen. Click through and approve the Google consent screen. Grant the requested scopes (Drive, Docs, Sheets, Slides, Calendar).

If you see *"Access limited to @relevantsearch.com accounts"* you signed in with the wrong Google account. Use the Google account switcher and retry with your work account.

After consent, you land back on claude.ai with the connector listed as **Connected**.

## 3. Try it

Open a new claude.ai chat and say:

> Use the Relevant Search Drive connector to list the 10 most recent files I've edited.

Expected result: Claude calls `search` and returns a list drawn from *your* Drive.

## Troubleshooting

| Symptom | What to do |
|---------|------------|
| claude.ai shows "Authentication failed" after Google consent | Retry. If it persists, check the [Cloud Run logs](https://console.cloud.google.com/run/detail/us-central1/drive-mcp/logs?project=rs-workspace-integrations) for the callback error. |
| Claude returns "No Google tokens stored for user" | Your tokens aged out or were revoked. Disconnect the connector in claude.ai settings and re-add it. |
| 401 on every tool call | The bearer JWT expired (1h TTL). claude.ai should refresh automatically; if not, reconnect. |
| Tools work but return empty results | Verify your Google account has access to the file/folder. The server acts strictly as *you* — no service-account fallback. |

## Revoking access

Two options:
1. **claude.ai side:** Settings → Connectors → Remove.
2. **Google side:** [myaccount.google.com/permissions](https://myaccount.google.com/permissions) → revoke "Relevant Search Drive MCP".

Both are idempotent. Doing the Google-side revoke alone breaks the connector on next tool call but leaves the claude.ai entry; clean up both when offboarding.

## For admins

The full architecture, infra, and deploy pipeline are documented in [`docs/projects/2026-04-15-drive-mcp-team/`](./projects/2026-04-15-drive-mcp-team/).

Runtime env is configured on the Cloud Run service `drive-mcp` in `rs-workspace-integrations`:

| Env var | Source |
|---------|--------|
| `PUBLIC_URL` | Literal: `https://drive-mcp.relevantsearch.com` |
| `MCP_SIGNING_KEY` | Secret Manager: `mcp-signing-key` |
| `GOOGLE_OAUTH_CLIENT_ID` | Secret Manager: `google-oauth-client-id` |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Secret Manager: `google-oauth-client-secret` |
| `ALLOWED_HOSTED_DOMAIN` | Literal: `relevantsearch.com` |

The Google OAuth client is internal-only (G Suite Internal app type), so no external consent review is needed.
