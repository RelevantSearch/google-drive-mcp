import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { DriveOAuthProvider } from '../../src/auth/provider.js';
import type { FirestoreStore } from '../../src/auth/firestore-store.js';
import type { GoogleOAuth } from '../../src/auth/google-oauth.js';
import type { McpJwt } from '../../src/auth/jwt.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Response } from 'express';

// Helper type for accessing mock internals without TS complaints
type MockFn = ReturnType<typeof mock.fn>;

/** Cast a mock method to access .mock context */
function asMock(fn: unknown): MockFn {
  return fn as MockFn;
}

/** Create a mock FirestoreStore with all methods stubbed. */
function createMockStore(): FirestoreStore {
  return {
    getOAuthClient: mock.fn(async () => undefined),
    saveOAuthClient: mock.fn(async () => {}),
    getUserTokens: mock.fn(async () => undefined),
    saveUserTokens: mock.fn(async () => {}),
    getPendingAuthorization: mock.fn(async () => undefined),
    savePendingAuthorization: mock.fn(async () => {}),
    deletePendingAuthorization: mock.fn(async () => {}),
    getAuthorizationCode: mock.fn(async () => undefined),
    saveAuthorizationCode: mock.fn(async () => {}),
    consumeAuthorizationCode: mock.fn(async () => undefined),
  } as unknown as FirestoreStore;
}

/** Create a mock GoogleOAuth. */
function createMockGoogleOAuth(): GoogleOAuth {
  return {
    authorizationUrl: mock.fn(() => 'https://accounts.google.com/o/oauth2/v2/auth?mock=1'),
    exchangeCode: mock.fn(async () => ({})),
    refreshAccessToken: mock.fn(async () => ({})),
  } as unknown as GoogleOAuth;
}

/** Create a mock McpJwt. */
function createMockJwt(): McpJwt {
  return {
    sign: mock.fn(async () => 'mock-jwt-token'),
    verify: mock.fn(async () => ({
      sub: 'google-user-123',
      email: 'user@relevantsearch.com',
      scope: 'openid email https://www.googleapis.com/auth/drive',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })),
  } as unknown as McpJwt;
}

const TEST_SCOPES = ['openid', 'email', 'https://www.googleapis.com/auth/drive'];
const PUBLIC_URL = 'https://drive-mcp.example.com';

const MOCK_CLIENT: OAuthClientInformationFull = {
  client_id: 'test-client-id-abc',
  client_secret: 'test-client-secret-xyz',
  redirect_uris: ['https://claude.ai/oauth/callback'],
} as OAuthClientInformationFull;

describe('DriveOAuthProvider', () => {
  let store: FirestoreStore;
  let googleOAuth: GoogleOAuth;
  let jwt: McpJwt;
  let provider: DriveOAuthProvider;

  beforeEach(() => {
    store = createMockStore();
    googleOAuth = createMockGoogleOAuth();
    jwt = createMockJwt();
    provider = new DriveOAuthProvider(store, googleOAuth, jwt, PUBLIC_URL, TEST_SCOPES);
  });

  describe('clientsStore getter', () => {
    it('returns an OAuthRegisteredClientsStore', () => {
      const cs = provider.clientsStore;
      assert.ok(cs);
      assert.equal(typeof cs.getClient, 'function');
      assert.equal(typeof cs.registerClient, 'function');
    });

    it('is a getter, not a plain property', () => {
      const descriptor = Object.getOwnPropertyDescriptor(
        DriveOAuthProvider.prototype,
        'clientsStore',
      );
      assert.ok(descriptor);
      assert.equal(typeof descriptor.get, 'function');
      assert.equal(descriptor.set, undefined);
    });
  });

  describe('clientsStore.getClient', () => {
    it('returns undefined for unknown client', async () => {
      const result = await provider.clientsStore.getClient('nonexistent');
      assert.equal(result, undefined);
    });

    it('returns client info from store (plaintext secret)', async () => {
      asMock(store.getOAuthClient).mock.mockImplementation(
        async () => ({
          client_id: 'test-client-id-abc',
          client_secret: 'test-client-secret-xyz',
          redirect_uris: ['https://claude.ai/oauth/callback'],
          created_at: new Date(),
        }),
      );

      const result = await provider.clientsStore.getClient('test-client-id-abc');
      assert.ok(result);
      assert.equal(result!.client_id, 'test-client-id-abc');
      // Secret stored as-is — NOT hashed
      assert.equal(result!.client_secret, 'test-client-secret-xyz');
      assert.deepEqual(result!.redirect_uris, ['https://claude.ai/oauth/callback']);
    });
  });

  describe('clientsStore.registerClient', () => {
    it('persists what SDK gives and returns it', async () => {
      // SDK generates client_id and client_secret before calling registerClient.
      // The Omit<> type is misleading — runtime object has these fields.
      const clientInfo = {
        client_id: 'sdk-generated-id',
        client_secret: 'sdk-generated-secret',
        redirect_uris: ['https://claude.ai/oauth/callback'],
        client_name: 'Claude Desktop',
      } as unknown as OAuthClientInformationFull;

      const result = await provider.clientsStore.registerClient!(clientInfo as any);
      assert.equal(result.client_id, 'sdk-generated-id');
      assert.equal(result.client_secret, 'sdk-generated-secret');

      // Verify saveOAuthClient was called with correct data
      const saveCall = asMock(store.saveOAuthClient).mock.calls[0];
      assert.ok(saveCall);
      const saved = saveCall.arguments[0] as any;
      assert.equal(saved.client_id, 'sdk-generated-id');
      assert.equal(saved.client_secret, 'sdk-generated-secret');
      assert.deepEqual(saved.redirect_uris, ['https://claude.ai/oauth/callback']);
      assert.ok(saved.created_at instanceof Date);
    });
  });

  describe('authorize', () => {
    it('redirects to Google with PKCE', async () => {
      let redirectUrl = '';
      let redirectStatus = 0;
      const mockRes = {
        redirect: mock.fn((status: number, url: string) => {
          redirectStatus = status;
          redirectUrl = url;
        }),
      } as unknown as Response;

      await provider.authorize(MOCK_CLIENT, {
        state: 'claude-state-123',
        codeChallenge: 'claude-pkce-challenge',
        redirectUri: 'https://claude.ai/oauth/callback',
      }, mockRes);

      // Should redirect with 302
      assert.equal(redirectStatus, 302);
      assert.ok(redirectUrl.includes('accounts.google.com'));

      // Should save pending authorization
      const saveCall = asMock(store.savePendingAuthorization).mock.calls[0];
      assert.ok(saveCall);
      const [googleState, pending] = saveCall.arguments as [string, any];
      assert.ok(googleState.length > 0);
      assert.equal(pending.claude_state, 'claude-state-123');
      assert.equal(pending.claude_code_challenge, 'claude-pkce-challenge');
      assert.equal(pending.claude_redirect_uri, 'https://claude.ai/oauth/callback');
      assert.equal(pending.claude_client_id, MOCK_CLIENT.client_id);
      assert.ok(pending.google_pkce_verifier.length > 0);
      assert.ok(pending.created_at instanceof Date);

      // Should call googleOAuth.authorizationUrl with google state/challenge/scopes
      const authCall = asMock(googleOAuth.authorizationUrl).mock.calls[0];
      assert.ok(authCall);
      assert.equal(authCall.arguments[0], googleState); // google state
      assert.ok((authCall.arguments[1] as string).length > 0); // google challenge
      assert.deepEqual(authCall.arguments[2], TEST_SCOPES);
    });

    it('handles optional state (empty string)', async () => {
      const mockRes = {
        redirect: mock.fn(() => {}),
      } as unknown as Response;

      await provider.authorize(MOCK_CLIENT, {
        codeChallenge: 'challenge',
        redirectUri: 'https://claude.ai/callback',
      }, mockRes);

      const saveCall = asMock(store.savePendingAuthorization).mock.calls[0];
      const pending = saveCall.arguments[1] as any;
      assert.equal(pending.claude_state, '');
    });
  });

  describe('challengeForAuthorizationCode', () => {
    it('returns stored PKCE challenge', async () => {
      asMock(store.getAuthorizationCode).mock.mockImplementation(
        async () => ({
          claude_code_challenge: 'the-stored-challenge',
          user_id: 'user-123',
          email: 'user@relevantsearch.com',
          google_access_token: 'gat',
          google_refresh_token: 'grt',
          google_token_expires_at: 9999999999,
          created_at: new Date(),
        }),
      );

      const challenge = await provider.challengeForAuthorizationCode(MOCK_CLIENT, 'auth-code-abc');
      assert.equal(challenge, 'the-stored-challenge');

      // Verify it uses non-consuming getAuthorizationCode (not consumeAuthorizationCode)
      assert.equal(
        asMock(store.getAuthorizationCode).mock.callCount(),
        1,
      );
      assert.equal(
        asMock(store.consumeAuthorizationCode).mock.callCount(),
        0,
      );
    });

    it('throws for unknown authorization code', async () => {
      await assert.rejects(
        () => provider.challengeForAuthorizationCode(MOCK_CLIENT, 'nonexistent-code'),
        (err: Error) => {
          assert.ok(err.message.includes('Unknown authorization code'));
          return true;
        },
      );
    });
  });

  describe('exchangeAuthorizationCode', () => {
    it('returns snake_case OAuthTokens with token_type bearer', async () => {
      asMock(store.consumeAuthorizationCode).mock.mockImplementation(
        async () => ({
          user_id: 'google-user-123',
          email: 'user@relevantsearch.com',
          claude_code_challenge: 'challenge',
          google_access_token: 'gat',
          google_refresh_token: 'grt',
          google_token_expires_at: 9999999999,
          created_at: new Date(),
        }),
      );

      const tokens = await provider.exchangeAuthorizationCode(MOCK_CLIENT, 'valid-code');

      // snake_case fields per RFC
      assert.equal(tokens.access_token, 'mock-jwt-token');
      assert.equal(tokens.token_type, 'bearer');
      assert.equal(tokens.expires_in, 3600);
      assert.equal(tokens.scope, TEST_SCOPES.join(' '));

      // Verify JWT was signed with correct claims
      const signCall = asMock(jwt.sign).mock.calls[0];
      const payload = signCall.arguments[0] as any;
      assert.equal(payload.sub, 'google-user-123');
      assert.equal(payload.email, 'user@relevantsearch.com');
      assert.equal(payload.scope, TEST_SCOPES.join(' '));
    });

    it('consumes authorization code atomically', async () => {
      asMock(store.consumeAuthorizationCode).mock.mockImplementation(
        async () => ({
          user_id: 'user-123',
          email: 'user@relevantsearch.com',
          claude_code_challenge: 'challenge',
          google_access_token: 'gat',
          google_refresh_token: 'grt',
          google_token_expires_at: 9999999999,
          created_at: new Date(),
        }),
      );

      await provider.exchangeAuthorizationCode(MOCK_CLIENT, 'code-to-consume');

      // Must use consumeAuthorizationCode (atomic get+delete), not getAuthorizationCode
      assert.equal(
        asMock(store.consumeAuthorizationCode).mock.callCount(),
        1,
      );
      assert.equal(
        asMock(store.getAuthorizationCode).mock.callCount(),
        0,
      );
    });

    it('throws for invalid/expired code', async () => {
      await assert.rejects(
        () => provider.exchangeAuthorizationCode(MOCK_CLIENT, 'expired-code'),
        (err: Error) => {
          assert.ok(err.message.includes('Invalid or expired authorization code'));
          return true;
        },
      );
    });
  });

  describe('exchangeRefreshToken', () => {
    it('throws "Refresh tokens not supported"', async () => {
      await assert.rejects(
        () => provider.exchangeRefreshToken(MOCK_CLIENT, 'some-refresh-token'),
        (err: Error) => {
          assert.ok(err.message.includes('Refresh tokens not supported'));
          return true;
        },
      );
    });
  });

  describe('verifyAccessToken', () => {
    it('returns AuthInfo with expiresAt from JWT exp', async () => {
      const expectedExp = Math.floor(Date.now() / 1000) + 3600;
      asMock(jwt.verify).mock.mockImplementation(
        async () => ({
          sub: 'google-user-123',
          email: 'user@relevantsearch.com',
          scope: 'openid email https://www.googleapis.com/auth/drive',
          exp: expectedExp,
        }),
      );

      const authInfo = await provider.verifyAccessToken('valid-jwt');

      assert.equal(authInfo.token, 'valid-jwt');
      assert.equal(authInfo.clientId, 'drive-mcp');
      assert.deepEqual(authInfo.scopes, ['openid', 'email', 'https://www.googleapis.com/auth/drive']);
      assert.equal(authInfo.expiresAt, expectedExp);
      assert.equal((authInfo.extra as any).userId, 'google-user-123');
      assert.equal((authInfo.extra as any).email, 'user@relevantsearch.com');
    });

    it('includes expiresAt (required for requireBearerAuth)', async () => {
      const authInfo = await provider.verifyAccessToken('some-token');
      // expiresAt MUST be defined — without it requireBearerAuth skips expiry checking
      assert.notEqual(authInfo.expiresAt, undefined);
      assert.equal(typeof authInfo.expiresAt, 'number');
    });

    it('propagates JWT verification errors', async () => {
      asMock(jwt.verify).mock.mockImplementation(
        async () => { throw new Error('JWT expired'); },
      );

      await assert.rejects(
        () => provider.verifyAccessToken('expired-token'),
        (err: Error) => {
          assert.ok(err.message.includes('JWT expired'));
          return true;
        },
      );
    });
  });
});
