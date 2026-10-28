/**
 * Integration tests for HTTP transport with OAuth wiring enabled.
 *
 * Exercises the real `createHttpApp({ authDeps })` code path with stub
 * implementations of FirestoreStore / GoogleOAuth — we are testing the wiring,
 * not the downstream services. Each test constructs a live `DriveOAuthProvider`
 * backed by the stubs, so `mcpAuthRouter` and `requireBearerAuth` execute as
 * they would in production.
 */

import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import type { Server as HttpServer } from 'node:http';
import * as zlib from 'node:zlib';

import { DriveOAuthProvider } from '../../src/auth/provider.js';
import { McpJwt } from '../../src/auth/jwt.js';
import type {
  OAuthClient,
  UserTokens,
  PendingAuthorization,
  AuthCodeRecord,
} from '../../src/auth/types.js';
import { assertValidFirestoreDocument } from '../helpers/firestore-doc-validation.js';

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

/** In-memory FirestoreStore stub — same shape as the real class. */
function makeStoreStub() {
  const oauthClients = new Map<string, OAuthClient>();
  const userTokens = new Map<string, UserTokens>();
  const pending = new Map<string, PendingAuthorization>();
  const authCodes = new Map<string, AuthCodeRecord>();

  return {
    _clients: oauthClients,
    _users: userTokens,
    _pending: pending,
    _codes: authCodes,
    async getOAuthClient(id: string) { return oauthClients.get(id); },
    async saveOAuthClient(c: OAuthClient) {
      assertValidFirestoreDocument(c);
      oauthClients.set(c.client_id, c);
    },
    async getUserTokens(id: string) { return userTokens.get(id); },
    async saveUserTokens(t: UserTokens) {
      assertValidFirestoreDocument(t);
      userTokens.set(t.user_id, t);
    },
    async getPendingAuthorization(state: string) { return pending.get(state); },
    async savePendingAuthorization(state: string, p: PendingAuthorization) {
      assertValidFirestoreDocument(p);
      pending.set(state, p);
    },
    async deletePendingAuthorization(state: string) { pending.delete(state); },
    async getAuthorizationCode(code: string) { return authCodes.get(code); },
    async saveAuthorizationCode(code: string, r: AuthCodeRecord) {
      assertValidFirestoreDocument(r);
      authCodes.set(code, r);
    },
    async consumeAuthorizationCode(code: string) {
      const rec = authCodes.get(code);
      if (!rec) return undefined;
      authCodes.delete(code);
      return rec;
    },
  };
}

function makeGoogleOAuthStub() {
  return {
    authorizationUrl: (state: string, challenge: string, scopes: string[]) =>
      `https://accounts.google.com/stub?state=${state}&challenge=${challenge}&scope=${scopes.join('+')}`,
    exchangeCode: async () => ({
      access_token: 'google-access-stub',
      refresh_token: 'google-refresh-stub',
      expires_in: 3600,
      token_type: 'Bearer',
      id_token: 'unused',
    }),
    refreshAccessToken: async () => ({
      access_token: 'google-access-stub-2',
      expires_in: 3600,
      token_type: 'Bearer',
    }),
  };
}

function buildTestAuthDeps() {
  const store = makeStoreStub() as any;
  const googleOAuth = makeGoogleOAuthStub() as any;
  const jwt = new McpJwt('test-signing-key-abcdefghijklmnop');
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

describe('HTTP transport — OAuth wiring', () => {
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

  it('serves /.well-known/oauth-authorization-server', async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(String(body.issuer).replace(/\/$/, ''), authDeps.publicUrl);
    assert.ok(Array.isArray(body.scopes_supported));
    assert.ok(body.scopes_supported.includes('openid'));
  });

  it('serves /.well-known/oauth-protected-resource', async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(String(body.resource).replace(/\/$/, ''), authDeps.publicUrl);
  });

  it('POST /mcp without bearer token returns 401', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } },
        id: 1,
      }),
    });
    assert.equal(res.status, 401);
  });

  it('POST /mcp with valid bearer token initializes session', async () => {
    const token = await authDeps.jwt.sign({
      sub: 'user-123',
      email: 'test@relevantsearch.com',
      scope: authDeps.scopes.join(' '),
    });

    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } },
        id: 1,
      }),
    });
    assert.equal(res.status, 200);
    const sid = res.headers.get('mcp-session-id');
    assert.ok(sid, 'session id should be returned');
  });

  it('GET /oauth/google/callback with unknown state returns 400', async () => {
    const res = await fetch(`${baseUrl}/oauth/google/callback?code=x&state=unknown`);
    assert.equal(res.status, 400);
  });

  it('GET /oauth/google/callback with missing params returns 400', async () => {
    const res = await fetch(`${baseUrl}/oauth/google/callback`);
    assert.equal(res.status, 400);
  });
});

describe('HTTP transport — refuses content-encoded bodies (CVE-2026-111497)', () => {
  const REG = {
    redirect_uris: ['http://localhost:33418/callback'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  };
  const registrationBody = JSON.stringify(REG);
  const brotliRegistrationBody = zlib.brotliCompressSync(registrationBody);
  const brotliMcpBody = zlib.brotliCompressSync(JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'initialize',
  }));
  const unsupportedEncodingError = {
    error: 'unsupported_content_encoding',
    error_description: 'compressed request bodies are not accepted',
  };
  let httpServer: HttpServer;
  let baseUrl: string;

  before(async () => {
    const mod = await getServerModule();
    const { app } = mod.createHttpApp('127.0.0.1', {
      authDeps: buildTestAuthDeps(),
      trustProxyHops: 2,
    });
    const started = await startServer(app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  const rejectedRequests = [
    { route: '/register', encoding: 'br', contentType: 'application/json', body: brotliRegistrationBody },
    { route: '/register', encoding: 'BR', contentType: 'application/json', body: brotliRegistrationBody },
    { route: '/register', encoding: 'identity, br', contentType: 'application/json', body: brotliRegistrationBody },
    { route: '/register', encoding: 'gzip', contentType: 'application/json', body: zlib.gzipSync(registrationBody) },
    {
      route: '/token', encoding: 'deflate', contentType: 'application/x-www-form-urlencoded',
      body: zlib.deflateSync('grant_type=authorization_code&code=x'),
    },
    { route: '/mcp', encoding: 'br', contentType: 'application/json', body: brotliMcpBody },
  ];

  for (const { route, encoding, contentType, body } of rejectedRequests) {
    it(`POST ${route} with Content-Encoding: ${encoding} returns 415 before auth or parsing`, async () => {
      const res = await fetch(`${baseUrl}${route}`, {
        method: 'POST',
        headers: { 'Content-Encoding': encoding, 'Content-Type': contentType },
        body,
      });
      assert.equal(res.status, 415);
      assert.deepEqual(await res.json(), unsupportedEncodingError);
    });
  }

  for (const encoding of ['identity', '']) {
    it(`POST /register with Content-Encoding: ${JSON.stringify(encoding)} returns 201`, async () => {
      const res = await fetch(`${baseUrl}/register`, {
        method: 'POST',
        headers: { 'Content-Encoding': encoding, 'Content-Type': 'application/json' },
        body: registrationBody,
      });
      assert.equal(res.status, 201);
      await res.json();
    });
  }

  it('POST /mcp with br returns 415 on the no-auth app', async () => {
    const mod = await getServerModule();
    const { app } = mod.createHttpApp('127.0.0.1');
    const started = await startServer(app);
    try {
      const res = await fetch(`${started.baseUrl}/mcp`, {
        method: 'POST',
        headers: { 'Content-Encoding': 'br', 'Content-Type': 'application/json' },
        body: brotliMcpBody,
      });
      assert.equal(res.status, 415);
      assert.deepEqual(await res.json(), unsupportedEncodingError);
    } finally {
      await new Promise<void>((resolve) => started.httpServer.close(() => resolve()));
    }
  });
});
