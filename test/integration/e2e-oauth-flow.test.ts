/**
 * End-to-end OAuth 2.1 flow with mocked Google.
 *
 * Exercises the full two-hop flow a claude.ai client performs:
 *
 *   1. GET /.well-known/oauth-authorization-server — discovery
 *   2. POST /register — dynamic client registration
 *   3. GET /authorize — redirects to (mocked) Google with PKCE
 *   4. GET /oauth/google/callback — mocked Google returns code, we mint our code
 *   5. POST /token — our code is exchanged for a bearer JWT
 *   6. JWT is decoded + used to authenticate against /mcp
 *
 * Google is stubbed so no network I/O touches accounts.google.com. The test
 * drives the same `DriveOAuthProvider` + `mcpAuthRouter` + `requireBearerAuth`
 * stack as production.
 */

import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import type { Server as HttpServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';

import { DriveOAuthProvider } from '../../src/auth/provider.js';
import { McpJwt } from '../../src/auth/jwt.js';
import type {
  OAuthClient,
  UserTokens,
  PendingAuthorization,
  AuthCodeRecord,
} from '../../src/auth/types.js';

let _serverModule: any = null;
async function getServerModule() {
  if (!_serverModule) _serverModule = await import('../../src/index.js');
  return _serverModule;
}

function startServer(app: any): Promise<{ httpServer: HttpServer; baseUrl: string }> {
  return new Promise((resolve) => {
    const httpServer = app.listen(0, '127.0.0.1', () => {
      const addr = httpServer.address();
      const baseUrl = addr && typeof addr === 'object' ? `http://127.0.0.1:${addr.port}` : '';
      resolve({ httpServer, baseUrl });
    });
  });
}

function makeStoreStub() {
  const oauthClients = new Map<string, OAuthClient>();
  const userTokens = new Map<string, UserTokens>();
  const pending = new Map<string, PendingAuthorization>();
  const authCodes = new Map<string, AuthCodeRecord>();

  return {
    async getOAuthClient(id: string) { return oauthClients.get(id); },
    async saveOAuthClient(c: OAuthClient) { oauthClients.set(c.client_id, c); },
    async getUserTokens(id: string) { return userTokens.get(id); },
    async saveUserTokens(t: UserTokens) { userTokens.set(t.user_id, t); },
    async getPendingAuthorization(state: string) { return pending.get(state); },
    async savePendingAuthorization(state: string, p: PendingAuthorization) { pending.set(state, p); },
    async deletePendingAuthorization(state: string) { pending.delete(state); },
    async getAuthorizationCode(code: string) { return authCodes.get(code); },
    async saveAuthorizationCode(code: string, r: AuthCodeRecord) { authCodes.set(code, r); },
    async consumeAuthorizationCode(code: string) {
      const rec = authCodes.get(code);
      if (!rec) return undefined;
      authCodes.delete(code);
      return rec;
    },
  };
}

const TEST_USER_SUB = '1234567890';
const TEST_USER_EMAIL = 'stefan@relevantsearch.com';

/** Unverified (test-only) id_token — callback code decodes without verifying signature. */
function makeFakeIdToken(sub: string, email: string, hd = 'relevantsearch.com'): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ sub, email, hd, iss: 'https://accounts.google.com' }),
  ).toString('base64url');
  return `${header}.${payload}.`;
}

function makeGoogleOAuthStub() {
  return {
    authorizationUrl: (state: string, challenge: string, scopes: string[]) =>
      `https://accounts.google.com/stub?state=${state}&challenge=${challenge}&scope=${scopes.join('+')}`,
    exchangeCode: async () => ({
      access_token: 'google-access-token',
      refresh_token: 'google-refresh-token',
      expires_in: 3600,
      token_type: 'Bearer',
      id_token: makeFakeIdToken(TEST_USER_SUB, TEST_USER_EMAIL),
    }),
    refreshAccessToken: async () => ({
      access_token: 'google-access-token-refreshed',
      expires_in: 3600,
      token_type: 'Bearer',
    }),
  };
}

function buildTestAuthDeps() {
  const store = makeStoreStub() as any;
  const googleOAuth = makeGoogleOAuthStub() as any;
  const jwt = new McpJwt('test-signing-key-e2e-1234567890abcdef');
  const publicUrl = 'http://127.0.0.1:9999';
  const scopes = ['openid', 'email', 'https://www.googleapis.com/auth/drive'];
  const provider = new DriveOAuthProvider(store, googleOAuth, jwt, publicUrl, scopes);
  return {
    provider,
    store,
    googleOAuth,
    jwt,
    publicUrl,
    allowedHostedDomain: 'relevantsearch.com',
    scopes,
  };
}

describe('E2E OAuth 2.1 flow (mocked Google)', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;
  let authDeps: ReturnType<typeof buildTestAuthDeps>;

  before(async () => {
    authDeps = buildTestAuthDeps();
    const mod = await getServerModule();
    const result = mod.createHttpApp('127.0.0.1', { authDeps });
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    for (const [, s] of sessions) {
      await s.transport.close();
      await s.server.close();
    }
    sessions.clear();
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  it('completes discovery → register → authorize → callback → token → /mcp', async () => {
    // ── 1. Discovery ────────────────────────────────────────────────
    // The metadata carries URLs built from publicUrl (the issuer). In tests
    // the actual listen port differs, so we only assert the endpoints exist
    // and re-derive paths against the live baseUrl.
    const meta = await (await fetch(`${baseUrl}/.well-known/oauth-authorization-server`)).json();
    assert.ok(meta.issuer);
    assert.ok(meta.registration_endpoint);
    assert.ok(meta.authorization_endpoint);
    assert.ok(meta.token_endpoint);

    const regEndpoint = `${baseUrl}${new URL(meta.registration_endpoint).pathname}`;
    const authorizeEndpoint = `${baseUrl}${new URL(meta.authorization_endpoint).pathname}`;
    const tokenEndpoint = `${baseUrl}${new URL(meta.token_endpoint).pathname}`;

    // ── 2. Dynamic client registration (RFC 7591) ───────────────────
    const regRes = await fetch(regEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'claude.ai (e2e)',
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
      }),
    });
    const regBody = await regRes.text();
    assert.equal(regRes.status, 201, regBody);
    const client = JSON.parse(regBody);
    assert.ok(client.client_id);
    assert.ok(client.client_secret);

    // ── 3. /authorize — we expect a 302 to (mocked) Google ──────────
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const claudeState = randomBytes(8).toString('hex');

    const authorizeUrl = new URL(authorizeEndpoint);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('client_id', client.client_id);
    authorizeUrl.searchParams.set('redirect_uri', 'https://claude.ai/api/mcp/auth_callback');
    authorizeUrl.searchParams.set('state', claudeState);
    authorizeUrl.searchParams.set('code_challenge', codeChallenge);
    authorizeUrl.searchParams.set('code_challenge_method', 'S256');
    authorizeUrl.searchParams.set('scope', authDeps.scopes.join(' '));

    const authRes = await fetch(authorizeUrl.toString(), { redirect: 'manual' });
    assert.equal(authRes.status, 302);
    const googleUrl = new URL(authRes.headers.get('location')!);
    assert.equal(googleUrl.hostname, 'accounts.google.com');
    const googleState = googleUrl.searchParams.get('state');
    assert.ok(googleState);

    // ── 4. Google callback — simulate Google redirecting back ───────
    const cbRes = await fetch(
      `${baseUrl}/oauth/google/callback?code=google-code&state=${googleState}`,
      { redirect: 'manual' },
    );
    assert.equal(cbRes.status, 302);
    const finalRedirect = new URL(cbRes.headers.get('location')!);
    assert.equal(finalRedirect.hostname, 'claude.ai');
    assert.equal(finalRedirect.searchParams.get('state'), claudeState);
    const ourCode = finalRedirect.searchParams.get('code');
    assert.ok(ourCode);

    // ── 5. /token — claude.ai exchanges our code for a bearer ───────
    const tokenRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: ourCode!,
        redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
        code_verifier: codeVerifier,
        client_id: client.client_id,
        client_secret: client.client_secret,
      }).toString(),
    });
    const tokenBody = await tokenRes.text();
    assert.equal(tokenRes.status, 200, tokenBody);
    const tokens = JSON.parse(tokenBody);
    assert.equal(tokens.token_type, 'bearer');
    assert.ok(tokens.access_token);
    assert.ok(typeof tokens.expires_in === 'number');

    // ── 6. JWT verifies + carries expected claims ───────────────────
    const payload = await authDeps.jwt.verify(tokens.access_token);
    assert.equal(payload.sub, TEST_USER_SUB);
    assert.equal(payload.email, TEST_USER_EMAIL);
    assert.ok(payload.exp);

    // ── 7. Initialize an MCP session with the bearer token ──────────
    const mcpRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'e2e-test', version: '1.0.0' },
        },
        id: 1,
      }),
    });
    const mcpBody = await mcpRes.text();
    assert.equal(mcpRes.status, 200, mcpBody);
    assert.ok(mcpRes.headers.get('mcp-session-id'));

    // ── 8. Our authorization code must be single-use ────────────────
    const replayRes = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: ourCode!,
        redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
        code_verifier: codeVerifier,
        client_id: client.client_id,
        client_secret: client.client_secret,
      }).toString(),
    });
    assert.ok(replayRes.status >= 400, 'replay of consumed code must not succeed');
  });

  it('rejects Google callback for non-allowed hosted domain', async () => {
    const badAuthDeps = buildTestAuthDeps();
    // Override exchangeCode to return a token for a non-relevantsearch.com user.
    badAuthDeps.googleOAuth.exchangeCode = async () => ({
      access_token: 'x',
      refresh_token: 'y',
      expires_in: 3600,
      token_type: 'Bearer',
      id_token: makeFakeIdToken('other-sub', 'rando@example.com', 'example.com'),
    });

    const mod = await getServerModule();
    const { app } = mod.createHttpApp('127.0.0.1', { authDeps: badAuthDeps });
    const started = await startServer(app);

    try {
      // Seed a pending authorization so the callback has state to consume.
      const googleState = 'fake-state-xyz';
      await badAuthDeps.store.savePendingAuthorization(googleState, {
        claude_state: 'claude-state',
        claude_code_challenge: 'challenge',
        claude_redirect_uri: 'https://claude.ai/cb',
        claude_client_id: 'some-client',
        google_pkce_verifier: 'verifier',
        created_at: new Date(),
      });

      const res = await fetch(
        `${started.baseUrl}/oauth/google/callback?code=x&state=${googleState}`,
      );
      assert.equal(res.status, 403);
    } finally {
      await new Promise<void>((resolve) => started.httpServer.close(() => resolve()));
    }
  });
});
