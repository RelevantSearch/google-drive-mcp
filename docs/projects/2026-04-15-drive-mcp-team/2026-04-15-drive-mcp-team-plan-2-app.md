---
version: 6
---

# Drive MCP — Plan 2: App (fork + OAuth server + deploy)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Steps use `- [ ]` syntax for tracking.

**Parent:** [index.md](./index.md) | **Design:** [design doc](./2026-04-15-drive-mcp-team-design.md) | **Prerequisite:** [Plan 1 (infra)](./2026-04-15-drive-mcp-team-plan-1-infra.md) — merged and applied.

**Goal:** Fork `piotr-agier/google-drive-mcp`, commit `createDocFromHTML`, add MCP-spec OAuth 2.1 using the SDK's own auth primitives (`OAuthServerProvider` + `mcpAuthRouter` + `requireBearerAuth`), and deploy to Cloud Run.

**Architecture:** Two-hop OAuth pattern (same as `chrisleekr/mcp-server-boilerplate` with Auth0, swapping Google). Our server acts as an OAuth AS to claude.ai AND as an OIDC RP to Google. `ProxyOAuthServerProvider` was evaluated and rejected — Google doesn't support Dynamic Client Registration, so the proxy can't forward claude.ai's dynamic `client_id`.

**Tech Stack:** TypeScript, Node 22 LTS, `@modelcontextprotocol/sdk` (>=1.26, pinned), `jose` (JWT), `@google-cloud/firestore`, `googleapis`, Node native test runner (`node:test` + `node:assert`).

**Worktree:** `~/git/RS/google-drive-mcp_feat-team-oauth/` (created in Task 1).

**Decision log (from 3 rounds of research):**

| Decision | Rationale |
|----------|-----------|
| **No better-auth** | 2 CVEs in 6 months (CVSS 9.3); zero production MCP deployments; single-maintainer Firestore adapter |
| **No `ProxyOAuthServerProvider`** | Google doesn't support DCR; proxy forwards claude.ai's dynamic client_id which Google rejects. Same finding by NapthaAI + vfarcic/dot-ai |
| **Custom `OAuthServerProvider`** | Full AS needed for two-hop pattern. Reference: `chrisleekr/mcp-server-boilerplate` (~600 LOC). All 6 required methods need real logic |
| **SDK `mcpAuthRouter`** | Routes `/.well-known/*`, `/authorize`, `/token`, `/register` automatically. Also serves `/.well-known/oauth-protected-resource` — no manual route needed |
| **Direct Google OAuth (`fetch`)** | Simpler than `googleapis` OAuth2Client |
| **Node native test runner** | Upstream uses `node --test` + `.tmp-test/` compilation |
| **Node 22 LTS** | Node 20 EOL Apr 30 2026 |
| **Firestore CMEK only for v1** | KMS envelope encryption deferred |
| **Stateless JWTs (1h TTL)** | claude.ai doesn't call revocation endpoints; `requireBearerAuth` checks `expiresAt` |

**SDK interfaces (verified in installed v1.26.0):**

```typescript
// OAuthServerProvider — ALL methods are required except revokeToken
interface OAuthServerProvider {
  get clientsStore(): OAuthRegisteredClientsStore;
  authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void>;
  challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string>;
  exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string,
    codeVerifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens>;
  exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string,
    scopes?: string[], resource?: URL): Promise<OAuthTokens>;
  verifyAccessToken(token: string): Promise<AuthInfo>;
  revokeToken?(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void>;
  skipLocalPkceValidation?: boolean;
}

// AuthorizationParams
type AuthorizationParams = {
  state?: string;       // optional
  scopes?: string[];
  codeChallenge: string;
  redirectUri: string;
  resource?: URL;
};

// OAuthTokens — snake_case per RFC
type OAuthTokens = {
  access_token: string;
  token_type: string;     // REQUIRED — "bearer"
  expires_in?: number;
  scope?: string;
  refresh_token?: string;
};

// OAuthRegisteredClientsStore
interface OAuthRegisteredClientsStore {
  getClient(clientId: string): OAuthClientInformationFull | undefined | Promise<...>;
  registerClient?(client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>):
    OAuthClientInformationFull | Promise<...>;
}

// OAuthClientInformationFull — RFC 7591 snake_case fields
// Key fields: client_id, client_secret, redirect_uris: string[], client_name, etc.

// AuthInfo — must include expiresAt for requireBearerAuth expiry checking
interface AuthInfo {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt?: number;     // seconds since epoch — MUST be set
  resource?: URL;
  extra?: Record<string, unknown>;
}

// Import paths (verified against actual node_modules):
// import type { OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
// import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
// import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
// import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
// import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
// import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
```

**SDK auth chain (verified):**

```
requireBearerAuth() → req.auth: AuthInfo
  → StreamableHTTPServerTransport.handleRequest(req) reads req.auth (line 134)
    → WebStandardStreamableHTTP passes authInfo to onmessage (lines 449, 478, 541)
      → Protocol._onmessage passes authInfo into RequestHandlerExtra (line 345)
        → setRequestHandler((request, extra) => extra.authInfo)
```

**Upstream codebase (verified):**

| Item | Location |
|------|----------|
| Entry point | `src/index.ts` — `startHttpTransport()` lines 583-726 |
| `buildToolContext()` | `src/index.ts` line 192 — takes 0 params, returns `ToolContext` with module-scoped `authClient` |
| Tool handler | `src/index.ts` line 339 — `async (request) => {}`, needs `(request, extra)` |
| Session model | Each HTTP session creates new `createMcpServer()` (line ~638) |
| Test runner | `node --test`, compiled via `tsconfig.test.json` to `.tmp-test/` |
| Test glob | `.tmp-test/test/**/*.test.js` — our `test/integration/` path will be picked up |
| Latest local | `master` at `f5ceac5` (v2.0.0) — verify against remote before forking |
| CI | `.github/workflows/ci.yml` + `publish.yml` exist — we add `deploy.yml` |
| License | MIT |

---

## File structure

**New files:**

```
src/auth/
├── provider.ts           # OAuthServerProvider: 6 required methods + clientsStore getter
├── firestore-store.ts    # clients + user_tokens + pending_authorizations + auth_codes
├── google-oauth.ts       # fetch-based Google token exchange + refresh
├── jwt.ts                # jose HS256 sign/verify
├── token-cache.ts        # in-memory Map with 10-min TTL
└── types.ts              # UserContext, internal store interfaces

src/pages/
└── sign-in.html          # "Sign in with Google" — redirects to Google auth URL

test/integration/
├── docs-from-html.test.ts
├── oauth-provider.test.ts
├── google-oauth.test.ts
├── middleware.test.ts
└── e2e.test.ts

.github/workflows/
└── deploy.yml
```

**Modified files:**

| File | Change |
|------|--------|
| `src/index.ts` | Mount `mcpAuthRouter`; add `requireBearerAuth` to `/mcp`; change handler to `(request, extra)`; refactor `buildToolContext(authInfo)` |
| `src/types.ts` | Add `user?: UserContext` to `ToolContext` |
| `src/tools/docs.ts` | Commit existing `createDocFromHTML` |
| `package.json` | Add deps; pin `@modelcontextprotocol/sdk` >=1.26; Node engine 22 |
| `Dockerfile` | Node 22 base image |

---

### Task 1: Fork from latest upstream

- [ ] **Step 1: Fork to RS org**

```bash
gh repo fork piotr-agier/google-drive-mcp --org relevantsearch --clone=false
```

- [ ] **Step 2: Clone the fork**

```bash
git -C ~/git/RS clone git@github.com:relevantsearch/google-drive-mcp.git google-drive-mcp-rs
```

- [ ] **Step 3: Create worktree from latest master**

```bash
git -C ~/git/RS/google-drive-mcp-rs fetch origin master
git -C ~/git/RS/google-drive-mcp-rs worktree add \
  ~/git/RS/google-drive-mcp_feat-team-oauth \
  -b feat/team-oauth origin/master
```

Note: local master is at `f5ceac5` (v2.0.0). Verify remote HEAD matches before forking — upstream may have newer commits.

---

### Task 2: Commit `createDocFromHTML` + baseline tests

- [ ] **Step 1: Copy the modified file**

```bash
cp ~/git/RS/google-drive-mcp/src/tools/docs.ts \
   ~/git/RS/google-drive-mcp_feat-team-oauth/src/tools/docs.ts
```

- [ ] **Step 2: Verify diff** — ~80 lines added

- [ ] **Step 3: Write test using Node native test runner**

Create `test/integration/docs-from-html.test.ts`:

```typescript
import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';
import { handleTool } from '../../src/tools/docs.js';

describe('createDocFromHTML', () => {
  const baseCtx = {
    getDrive: mock.fn(),
    resolveFolderId: mock.fn(async () => 'folder-123'),
    checkFileExists: mock.fn(async () => null),
    log: mock.fn(),
  } as any;

  it('creates a doc from HTML', async () => {
    baseCtx.getDrive.mock.mockImplementation(() => ({
      files: {
        create: mock.fn(async () => ({
          data: { id: 'doc-1', name: 'Test', webViewLink: 'https://docs.google.com/document/d/doc-1' },
        })),
      },
    }));

    const result = await handleTool('createDocFromHTML', {
      html: '<h1>Hi</h1><p>Body</p>',
      name: 'Test',
    }, baseCtx);

    assert.ok(!result.isError);
  });

  it('rejects duplicate name', async () => {
    baseCtx.checkFileExists.mock.mockImplementationOnce(async () => 'existing-id');
    const result = await handleTool('createDocFromHTML', {
      html: '<p>x</p>',
      name: 'Dupe',
    }, baseCtx);
    assert.ok(result.isError);
  });
});
```

- [ ] **Step 4: Run baseline tests** — `npm test` — verify upstream + new test pass

- [ ] **Step 5: Commit**

```bash
git add src/tools/docs.ts test/integration/docs-from-html.test.ts
git commit -m "feat(docs): add createDocFromHTML tool"
```

---

### Task 3: Add dependencies + update Node to 22

- [ ] **Step 1: Install**

```bash
npm install jose @google-cloud/firestore
```

Verify `@modelcontextprotocol/sdk` >= 1.26 in `package.json`. If < 1.26, upgrade: `npm install @modelcontextprotocol/sdk@latest`.

- [ ] **Step 2: Update Dockerfile to Node 22**

Change base image `FROM node:20-alpine` → `FROM node:22-alpine`.

- [ ] **Step 3: Verify build** — `npm run build`

- [ ] **Step 4: Commit**

```bash
git add package.json package-lock.json Dockerfile
git commit -m "chore: add jose + firestore deps, update Node to 22 LTS"
```

---

### Task 4: Firestore store + Google OAuth + JWT + token cache

Four small focused modules. No framework dependency.

**Files:** Create `src/auth/types.ts`, `src/auth/firestore-store.ts`, `src/auth/google-oauth.ts`, `src/auth/jwt.ts`, `src/auth/token-cache.ts`, `test/integration/google-oauth.test.ts`

- [ ] **Step 1: Create `src/auth/types.ts`** — internal store interfaces. Note: `OAuthClient.client_secret` is plaintext (SDK does direct comparison; do NOT hash). See v6 changelog for rationale.

- [ ] **Step 2: Implement `src/auth/firestore-store.ts`** — CRUD for `oauth_clients`, `user_tokens`, `pending_authorizations`, `authorization_codes`. **IMPORTANT:** `consumeAuthorizationCode()` MUST use a Firestore transaction (`db.runTransaction()`) to atomically get + delete the code record — prevents double-mint race if concurrent `/token` requests hit with the same code. `getAuthorizationCode()` (non-consuming read for `challengeForAuthorizationCode`) does NOT need a transaction.

- [ ] **Step 3: Implement `src/auth/google-oauth.ts`** — `fetch`-based Google token exchange + refresh. Includes `InvalidGrantError`.

- [ ] **Step 4: Implement `src/auth/jwt.ts`** — `jose` HS256. `sign()` returns token string, `verify()` returns payload with `sub`, `email`, `scope`, `exp`.

- [ ] **Step 5: Implement `src/auth/token-cache.ts`** — in-memory `Map<userId, {token, expiresAt}>` with 10-min TTL. Export `getCachedToken()`, `setCachedToken()`, `deleteCachedToken()` — delete is called on `InvalidGrantError` to clear stale entries.

- [ ] **Step 6: Write tests** — Google OAuth code exchange, refresh, `invalid_grant` using mock `fetch`

- [ ] **Step 7: Commit**

```bash
git add src/auth/ test/integration/
git commit -m "feat(auth): add Firestore store, Google OAuth, JWT, token cache"
```

---

### Task 5: Implement `OAuthServerProvider`

Core auth task. All 6 required methods implemented. `mcpAuthRouter` wires routes automatically.

**Files:** Create `src/auth/provider.ts`, `test/integration/oauth-provider.test.ts`

**Reference implementation:** `chrisleekr/mcp-server-boilerplate` `src/core/server/auth/services/oauthService.ts`

- [ ] **Step 1: Write failing test**

```typescript
import { describe, it, mock } from 'node:test';
import assert from 'node:assert/strict';

describe('DriveOAuthProvider', () => {
  it('registers a client dynamically', async () => { /* test clientsStore.registerClient() */ });
  it('authorize redirects to Google with PKCE', async () => { /* test authorize() */ });
  it('challengeForAuthorizationCode returns stored challenge', async () => { /* CRITICAL: test this */ });
  it('exchanges auth code for OAuthTokens (snake_case)', async () => { /* test exchangeAuthorizationCode() */ });
  it('exchangeRefreshToken issues new access token', async () => { /* test exchangeRefreshToken() */ });
  it('verifyAccessToken returns AuthInfo with expiresAt', async () => { /* test verifyAccessToken() */ });
  it('rejects non-@relevantsearch.com users at callback', async () => { /* domain check */ });
});
```

- [ ] **Step 2: Implement `src/auth/provider.ts`**

```typescript
import type { OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Response } from 'express';
import { FirestoreStore } from './firestore-store.js';
import { GoogleOAuth } from './google-oauth.js';
import { McpJwt } from './jwt.js';
import { createHash, randomBytes } from 'crypto';

export class DriveOAuthProvider implements OAuthServerProvider {
  // Must be a getter per SDK interface
  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  private _clientsStore: OAuthRegisteredClientsStore;

  constructor(
    private readonly store: FirestoreStore,
    private readonly googleOAuth: GoogleOAuth,
    private readonly jwt: McpJwt,
    private readonly publicUrl: string,
    private readonly scopes: string[],
  ) {
    this._clientsStore = {
      getClient: async (clientId: string): Promise<OAuthClientInformationFull | undefined> => {
        const doc = await store.getOAuthClient(clientId);
        if (!doc) return undefined;
        // Return as-is — SDK's authenticateClient does direct string comparison
        // on client_secret. Do NOT hash.
        return {
          client_id: doc.client_id,
          client_secret: doc.client_secret,  // plaintext, not hashed
          redirect_uris: doc.redirect_uris,
        } as OAuthClientInformationFull;
      },
      // SDK generates client_id + client_secret BEFORE calling registerClient.
      // We just persist what the SDK gives us.
      registerClient: async (
        clientInfo: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>
      ): Promise<OAuthClientInformationFull> => {
        await store.saveOAuthClient({
          client_id: (clientInfo as any).client_id,
          client_secret: (clientInfo as any).client_secret,  // store as-is
          redirect_uris: clientInfo.redirect_uris || [],
          created_at: new Date(),
        });
        return clientInfo as OAuthClientInformationFull;
      },
    };
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: { state?: string; codeChallenge: string; redirectUri: string; scopes?: string[]; resource?: URL },
    res: Response,
  ): Promise<void> {
    const googleVerifier = randomBytes(32).toString('base64url');
    const googleChallenge = createHash('sha256').update(googleVerifier).digest('base64url');
    const googleState = randomBytes(16).toString('hex');

    await this.store.savePendingAuthorization(googleState, {
      claude_state: params.state || '',
      claude_code_challenge: params.codeChallenge,
      claude_redirect_uri: params.redirectUri,
      claude_client_id: client.client_id,
      google_pkce_verifier: googleVerifier,
      created_at: new Date(),
    });

    const googleUrl = this.googleOAuth.authorizationUrl(googleState, googleChallenge, this.scopes);
    res.redirect(302, googleUrl);
  }

  // REQUIRED: returns stored PKCE challenge for the authorization code.
  // mcpAuthRouter's token handler calls this before exchangeAuthorizationCode.
  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const record = await this.store.getAuthorizationCode(authorizationCode);
    if (!record) throw new Error('Unknown authorization code');
    return record.claude_code_challenge;
  }

  async exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    _redirectUri?: string,
    _resource?: URL,
  ): Promise<OAuthTokens> {
    const record = await this.store.consumeAuthorizationCode(authorizationCode);
    if (!record) throw new Error('Invalid or expired authorization code');

    const accessToken = await this.jwt.sign({
      sub: record.subject,
      email: record.email,
      scope: this.scopes.join(' '),
    });

    // Return snake_case OAuthTokens per RFC
    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: 3600,
      scope: this.scopes.join(' '),
    };
  }

  // REQUIRED: must exist. For v1, we don't support refresh — return error.
  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    _refreshToken: string,
    _scopes?: string[],
    _resource?: URL,
  ): Promise<OAuthTokens> {
    throw new Error('Refresh tokens not supported — reconnect to get a new access token');
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const payload = await this.jwt.verify(token);
    return {
      token,
      clientId: 'drive-mcp',  // static — JWT doesn't carry clientId; value is informational
      scopes: payload.scope?.split(' ') || [],
      expiresAt: payload.exp,  // MUST include for requireBearerAuth expiry checking
      extra: { userId: payload.sub, email: payload.email },
    };
  }

  // revokeToken is optional — not implemented for v1
}
```

**Key differences from v4:**
- `get clientsStore()` getter syntax (not property assignment)
- `OAuthClientInformationFull` type with `client_id` / `redirect_uris` (snake_case)
- `OAuthRegisteredClientsStore` imported from `server/auth/clients.js`
- `challengeForAuthorizationCode()` — returns stored PKCE challenge
- `exchangeRefreshToken()` — throws (required but not supported in v1)
- `exchangeAuthorizationCode()` returns `OAuthTokens` (snake_case, includes `token_type: 'bearer'`)
- `verifyAccessToken()` returns `expiresAt` from JWT `exp` claim
- `authorize()` params use SDK's `AuthorizationParams` shape (`state?` optional, `resource?` optional)

- [ ] **Step 3: Run tests, commit**

```bash
git add src/auth/provider.ts test/integration/oauth-provider.test.ts
git commit -m "feat(auth): implement OAuthServerProvider with all 6 required methods"
```

---

### Task 6: Wire auth into HTTP transport

**Files:** Modify `src/index.ts`, create `src/pages/sign-in.html`

- [ ] **Step 1: Add Google callback route**

Express route `/oauth/google/callback` — outside the SDK provider. **This is the most critical data flow in the auth chain.** Code:

```typescript
async function googleCallbackHandler(req: Request, res: Response) {
  const { code, state: googleState, error } = req.query as Record<string, string>;
  if (error) return res.status(400).send(`Google error: ${error}`);
  if (!code || !googleState) return res.status(400).json({ error: 'invalid_request' });

  // 1. Look up the pending authorization by Google state
  const pending = await store.getPendingAuthorization(googleState);
  if (!pending) return res.status(400).json({ error: 'unknown_state' });
  await store.deletePendingAuthorization(googleState);

  // 2. Exchange Google code for tokens
  const tokens = await googleOAuth.exchangeCode(code, pending.google_pkce_verifier);
  if (!tokens.refresh_token || !tokens.id_token) {
    return res.status(400).json({ error: 'missing_tokens' });
  }

  // 3. Validate domain from ID token
  // NOTE: We trust this ID token because we just exchanged the code directly
  // with Google's token endpoint over HTTPS (not received from a client).
  // Full signature verification is unnecessary in this server-to-server flow
  // per Google's guidance: https://developers.google.com/identity/protocols/oauth2/openid-connect#obtainuserinfo
  const [, payloadB64] = tokens.id_token.split('.');
  const idPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  if (idPayload.hd !== 'relevantsearch.com') {
    return res.status(403).send('Only @relevantsearch.com accounts');
  }

  // 4. Store user's Google tokens in Firestore
  await store.saveUserTokens(idPayload.sub, {
    email: idPayload.email,
    google_refresh_token: tokens.refresh_token,
    google_subject: idPayload.sub,
    scopes: scopes,
    created_at: new Date(),
    last_refreshed_at: new Date(),
  });

  // 5. Generate OUR authorization code — MUST include claude_code_challenge
  //    for challengeForAuthorizationCode() to work (PKCE verification chain)
  const authCode = randomBytes(32).toString('hex');
  await store.saveAuthorizationCode(authCode, {
    subject: idPayload.sub,
    email: idPayload.email,
    claude_client_id: pending.claude_client_id,
    claude_code_challenge: pending.claude_code_challenge,  // CRITICAL: copied from pending
    expires_at: new Date(Date.now() + 60_000),
  });

  // 6. Redirect back to claude.ai with our code + claude's original state
  const redirect = new URL(pending.claude_redirect_uri);
  redirect.searchParams.set('code', authCode);
  if (pending.claude_state) redirect.searchParams.set('state', pending.claude_state);
  res.redirect(302, redirect.toString());
}
```

- [ ] **Step 2: Create sign-in page**

`src/pages/sign-in.html` — since `authorize()` redirects directly to Google, the sign-in page is only shown if the user navigates directly. Use a simple page that redirects to `/authorize` with the right params, or just shows a message.

- [ ] **Step 3: Mount `mcpAuthRouter`**

In `startHttpTransport()`, before existing `/mcp` routes:

```typescript
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { DriveOAuthProvider } from './auth/provider.js';

const provider = new DriveOAuthProvider(store, googleOAuth, jwt, publicUrl, scopes);

// SDK auto-wires: /.well-known/oauth-authorization-server,
//   /.well-known/oauth-protected-resource, /authorize, /token, /register
app.use(mcpAuthRouter({ provider, issuerUrl: new URL(publicUrl) }));

// Google callback (outside SDK — completes the two-hop flow)
app.get('/oauth/google/callback', googleCallbackHandler);

// NOTE: do NOT add manual /.well-known/oauth-protected-resource route —
// mcpAuthRouter already serves it
```

- [ ] **Step 4: Add `requireBearerAuth` to /mcp routes**

```typescript
const authMiddleware = requireBearerAuth({ verifier: provider });
app.post('/mcp', authMiddleware, async (req, res) => { /* existing */ });
app.get('/mcp', authMiddleware, async (req, res) => { /* existing */ });
app.delete('/mcp', authMiddleware, async (req, res) => { /* existing */ });
```

- [ ] **Step 5: Refactor `buildToolContext(authInfo)`**

Change from 0-param to accepting `AuthInfo`:

```typescript
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

function buildToolContext(authInfo: AuthInfo): ToolContext {
  const userId = authInfo.extra?.userId as string;
  const email = authInfo.extra?.email as string;

  const getToken = async () => {
    const cached = getCachedToken(userId);
    if (cached) return cached;
    const tokens = await store.getUserTokens(userId);
    if (!tokens) throw new Error('No Google tokens for user');
    try {
      const accessToken = await googleOAuth.refreshAccessToken(tokens.google_refresh_token);
      setCachedToken(userId, accessToken);
      return accessToken;
    } catch (e) {
      deleteCachedToken(userId);  // clear stale entry on error
      throw e;
    }
  };

  const perUserAuth = { getAccessToken: async () => ({ token: await getToken() }) };

  return {
    authClient: perUserAuth,
    google: googleapis,
    getDrive: () => google.drive({ version: 'v3', auth: perUserAuth as any }),
    getCalendar: () => google.calendar({ version: 'v3', auth: perUserAuth as any }),
    // ... other existing fields (log, resolvePath, resolveFolderId, etc.)
    user: { subject: userId, email, getGoogleAccessToken: getToken },
  };
}
```

- [ ] **Step 6: Update tool handler signature**

At line ~339, change:
```typescript
// FROM:
s.setRequestHandler(CallToolRequestSchema, async (request) => {
  const ctx = buildToolContext();
// TO:
s.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  const ctx = buildToolContext(extra.authInfo!);
```

- [ ] **Step 7: Build + typecheck, commit**

```bash
npm run build
git add src/ .
git commit -m "feat(transport): wire MCP auth into HTTP transport"
```

---

### Task 7: E2E test

- [ ] **Step 1: Write E2E test with mocked Google**

Test chain: discovery → register → authorize → google callback (mocked) → token → decode JWT.

- [ ] **Step 2: Run full test suite** — `npm test`

- [ ] **Step 3: Commit**

```bash
git add test/integration/e2e.test.ts
git commit -m "test(auth): add E2E OAuth flow test"
```

---

### Task 8: Deployer SA + WIF (prerequisite rs_infra PR)

**MUST be merged and applied BEFORE the app PR merge.**

- [ ] **Step 1: Add deployer SA** to `modules/workspace-integrations-mcp/iam.tf`:

```hcl
resource "google_service_account" "drive_mcp_deployer" {
  project      = var.project_id
  account_id   = "${var.service_name}-deployer"
  display_name = "Drive MCP CI deployer"
}

resource "google_project_iam_member" "deployer_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.drive_mcp_deployer.email}"
}

resource "google_project_iam_member" "deployer_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.drive_mcp_deployer.email}"
}

resource "google_service_account_iam_member" "deployer_act_as_runtime" {
  service_account_id = google_service_account.drive_mcp.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.drive_mcp_deployer.email}"
}
```

- [ ] **Step 2: Add WIF binding**

The WIF pool (`github-pool`) is in `rs-infra` project (`547220269732`). Current bootstrap (`environments/bootstrap/wif-github-actions/`) only has `rs_infra` repo. Need to add a `principalSet` binding scoped to `RelevantSearch/google-drive-mcp` → `drive-mcp-deployer` SA.

Either extend the WIF module or add a direct `google_service_account_iam_member` with `workloadIdentityUser` role.

- [ ] **Step 3: PR, CI, merge, apply, verify**

---

### Task 9: GitHub Actions workflow

- [ ] **Step 1: Create `.github/workflows/deploy.yml`**

```yaml
name: CI and Deploy

on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]

env:
  PROJECT_ID: rs-workspace-integrations
  REGION: us-central1
  SERVICE: drive-mcp
  REPO: drive-mcp
  WIF_PROVIDER: projects/547220269732/locations/global/workloadIdentityPools/github-pool/providers/github-provider
  DEPLOY_SA: drive-mcp-deployer@rs-workspace-integrations.iam.gserviceaccount.com

permissions:
  contents: read
  id-token: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npm run lint
      - run: npm run build
      - run: npm test

  deploy:
    needs: test
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ env.WIF_PROVIDER }}
          service_account: ${{ env.DEPLOY_SA }}
      - uses: google-github-actions/setup-gcloud@v2
      - name: Configure Docker
        run: gcloud auth configure-docker ${{ env.REGION }}-docker.pkg.dev --quiet
      - name: Build and push image
        run: |
          TAG="${{ env.REGION }}-docker.pkg.dev/${{ env.PROJECT_ID }}/${{ env.REPO }}/${{ env.SERVICE }}:${{ github.sha }}"
          docker build -t "$TAG" .
          docker push "$TAG"
          echo "IMAGE=$TAG" >> $GITHUB_ENV
      - name: Deploy to Cloud Run
        run: |
          gcloud run deploy ${{ env.SERVICE }} \
            --image="${{ env.IMAGE }}" \
            --project="${{ env.PROJECT_ID }}" \
            --region="${{ env.REGION }}" \
            --quiet
```

- [ ] **Step 2: Commit**

---

### Task 10: README + team onboarding

- [ ] **Step 1-4:** Add RS fork README section, create `docs/team-connector-setup.md`, copy design + plan docs from `~/git/RS/main/rs_infra/docs/projects/2026-04-15-drive-mcp-team/`, commit.

---

### Task 11: Open PR

- [ ] **Step 1-3:** Push, open PR, monitor CI + address comments.

---

### Task 12: Post-merge smoke test

- [ ] **Step 1: Verify Cloud Run deployed new image**
- [ ] **Step 2: Hit discovery endpoints**

```bash
curl -sSf https://drive-mcp.relevantsearch.com/.well-known/oauth-protected-resource | jq .
curl -sSf https://drive-mcp.relevantsearch.com/.well-known/oauth-authorization-server | jq .
```

- [ ] **Step 3: Stefan adds connector in claude.ai, completes Google sign-in, tests `createDocFromHTML`**

Note: MCP conformance suite (`@modelcontextprotocol/conformance`) does NOT have an `auth` suite — it tests protocol mechanics (initialize, tools, resources), not OAuth. Auth is validated by the E2E test in Task 7 and by Stefan's manual connector test here.

---

## Done criteria

- [ ] All 12 tasks complete
- [ ] PR merged, Cloud Run serves the fork
- [ ] Both discovery endpoints return valid metadata
- [ ] Stefan completes Google sign-in via claude.ai connector
- [ ] `createDocFromHTML` produces a branded doc in Stefan's Drive
- [ ] 2-3 additional team members enabled and verified

## Changelog

### v6 — 2026-04-20
- CRITICAL: `client_secret` must NOT be hashed — SDK does direct string comparison in `authenticateClient`. Store and return as-is. SDK generates `client_id`/`client_secret` before calling `registerClient` — don't duplicate.
- MAJOR: Added explicit Google callback code in Task 6 showing `claude_code_challenge` copied from `pending_authorizations` into auth code record (PKCE chain depends on this)
- MAJOR: `consumeAuthorizationCode` must use Firestore transaction for atomic get+delete
- MINOR: Added `deleteCachedToken()` export + error handling in `buildToolContext` catch block
- MINOR: Removed MCP conformance smoke test from Task 12 (no `--suite auth` exists)
- All SDK imports, types, and method signatures verified 100% correct (round 4 task-by-task)
- PKCE flow verified against actual SDK token handler source code
- Token expiry chain verified: jose exp → AuthInfo.expiresAt → requireBearerAuth — all seconds-since-epoch

### v5 — 2026-04-20
- Fixed all critical defects from round 3 research:
  - Added `challengeForAuthorizationCode()` (MUST per SDK — PKCE verification fails without it)
  - Added `exchangeRefreshToken()` (MUST — throws Not implemented for v1)
  - Fixed return type to `OAuthTokens` (snake_case: `access_token`, `token_type: 'bearer'`)
  - Fixed client types to `OAuthClientInformationFull` (RFC 7591 snake_case)
  - Fixed `clientsStore` to getter syntax (`get clientsStore()`)
  - Fixed `OAuthRegisteredClientsStore` import from `server/auth/clients.js`
  - Added `expiresAt` to `AuthInfo` in `verifyAccessToken()`
  - Removed duplicate `/.well-known/oauth-protected-resource` route (mcpAuthRouter serves it)
- Confirmed `ProxyOAuthServerProvider` doesn't fit (Google rejects dynamic client_id)
- Added reference implementation pointer: `chrisleekr/mcp-server-boilerplate`
- Added `Firestore.getAuthorizationCode()` for non-consuming reads (needed by `challengeForAuthorizationCode`)
- Documented claude.ai bug: ignores external AS endpoints (co-located pattern works around it)
- Documented stateless JWT + no revocation is acceptable (claude.ai never calls revocation)
- Corrected upstream commit to `f5ceac5` (v2.0.0)

### v4 — 2026-04-20
- SDK-native auth (OAuthServerProvider + mcpAuthRouter + requireBearerAuth)

### v3 — 2026-04-20
- Rewrite with better-auth (rejected in v4)

### v2 — 2026-04-20
- Plan 1 change adjustments

### v1 — 2026-04-15
- Initial plan
