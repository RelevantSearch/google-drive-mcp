/**
 * Integration tests for dynamic client registration of PUBLIC clients
 * (token_endpoint_auth_method "none" — what Claude Code registers as).
 *
 * Exercises the real `createHttpApp({ authDeps })` path so the SDK's
 * mcpAuthRouter /register handler runs as in production. The store stub
 * rejects documents containing undefined values with the same client-side
 * validation the real @google-cloud/firestore client performs before any
 * network I/O (see test/helpers/firestore-doc-validation.ts).
 *
 * The SDK sets client_secret: undefined on the clientInfo it passes to
 * registerClient for public clients, so a registerClient that forwards the
 * field verbatim turns every public-client registration into a 500.
 */

import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import type { Server as HttpServer } from 'node:http';

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

/** In-memory FirestoreStore stub that validates writes like real Firestore. */
function makeStoreStub() {
  const oauthClients = new Map<string, OAuthClient>();
  const userTokens = new Map<string, UserTokens>();
  const pending = new Map<string, PendingAuthorization>();
  const authCodes = new Map<string, AuthCodeRecord>();

  return {
    _clients: oauthClients,
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
    exchangeCode: async () => ({}),
    refreshAccessToken: async () => ({}),
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

describe('Dynamic client registration — public clients', () => {
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

  it('POST /register with token_endpoint_auth_method "none" returns 201 without a client_secret', async () => {
    const res = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Claude Code',
        redirect_uris: ['http://localhost:33418/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    });
    const body = await res.json();
    assert.equal(res.status, 201, `expected 201, got ${res.status}: ${JSON.stringify(body)}`);
    assert.ok(body.client_id, 'response must carry a client_id');
    assert.equal(body.client_secret, undefined, 'public client must not receive a client_secret');
  });

  it('persists the public client without a client_secret field', async () => {
    const res = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Claude Code',
        redirect_uris: ['http://localhost:33418/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    });
    const body = await res.json();
    assert.equal(res.status, 201);

    const stored = authDeps.store._clients.get(body.client_id);
    assert.ok(stored, 'client document must be persisted');
    assert.equal(
      'client_secret' in stored,
      false,
      'stored document must omit client_secret entirely — undefined is not a valid Firestore value',
    );
  });

  it('read-back of a public client yields no client_secret, so token auth stays PKCE-only', async () => {
    const res = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['http://localhost:33418/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    });
    const body = await res.json();
    assert.equal(res.status, 201);

    // SDK's authenticateClient only demands a secret when the stored client
    // has a truthy client_secret — a secretless read-back keeps the client public.
    const client = await authDeps.provider.clientsStore.getClient(body.client_id);
    assert.ok(client, 'registered client must be readable back');
    assert.ok(!client!.client_secret, 'public client read-back must have no client_secret');
  });

  it('still registers confidential clients with a client_secret (regression guard)', async () => {
    const res = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'claude.ai',
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_post',
      }),
    });
    const body = await res.json();
    assert.equal(res.status, 201);
    assert.ok(body.client_id);
    assert.ok(body.client_secret, 'confidential client must receive a client_secret');

    const stored = authDeps.store._clients.get(body.client_id);
    assert.ok(stored);
    assert.equal(stored!.client_secret, body.client_secret);
  });
});
