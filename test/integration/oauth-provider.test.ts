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
    verifyAllowExpired: mock.fn(async () => ({
      sub: 'google-user-123',
      email: 'user@relevantsearch.com',
      scope: 'openid email https://www.googleapis.com/auth/drive',
      exp: Math.floor(Date.now() / 1000) + 3600,
    })),
  } as unknown as McpJwt;
}

function createMockRefreshTokenStore() {
  return {
    issue: mock.fn(async (_p: any) => ({
      rawToken: 'mock-refresh-token-raw',
      chainId: 'mock-chain-id',
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    })),
    validate: mock.fn(async (_t: string) => null),
    rotate: mock.fn(async (_t: string) => ({
      rawToken: 'mock-rotated-token-raw',
      chainId: 'mock-chain-id',
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    })),
    revokeChain: mock.fn(async (_c: string) => {}),
    revokeUser: mock.fn(async (_u: string) => {}),
  };
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
  let refreshTokenStore: ReturnType<typeof createMockRefreshTokenStore>;

  beforeEach(() => {
    store = createMockStore();
    googleOAuth = createMockGoogleOAuth();
    jwt = createMockJwt();
    refreshTokenStore = createMockRefreshTokenStore();
    provider = new DriveOAuthProvider(
      store, googleOAuth, jwt, PUBLIC_URL, TEST_SCOPES, refreshTokenStore as any,
    );
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

    it('rejects a code older than AUTH_CODE_MAX_AGE_MS', async () => {
      asMock(store.consumeAuthorizationCode).mock.mockImplementation(async () => ({
        claude_code_challenge: 'challenge',
        user_id: 'user-123',
        email: 'stefan@relevantsearch.com',
        google_access_token: 'google-access',
        google_refresh_token: 'google-refresh',
        google_token_expires_at: Math.floor(Date.now() / 1000) + 3600,
        // Issued more than 60s ago.
        created_at: new Date(Date.now() - 61_000),
      }));

      await assert.rejects(
        () => provider.exchangeAuthorizationCode(MOCK_CLIENT, 'stale-code'),
        (err: Error) => {
          assert.ok(err.message.includes('Invalid or expired authorization code'));
          return true;
        },
      );
    });
  });

  describe('exchangeAuthorizationCode (with refresh token)', () => {
    beforeEach(() => {
      asMock(store.consumeAuthorizationCode).mock.mockImplementation(async () => ({
        claude_code_challenge: 'cc',
        user_id: 'google-user-123',
        email: 'user@relevantsearch.com',
        google_access_token: 'g-access',
        google_refresh_token: 'g-refresh',
        google_token_expires_at: Math.floor(Date.now() / 1000) + 3600,
        created_at: new Date(),
      }));
    });

    it('returns both access_token and refresh_token', async () => {
      const tokens = await provider.exchangeAuthorizationCode(MOCK_CLIENT, 'some-auth-code');
      assert.equal(tokens.access_token, 'mock-jwt-token');
      assert.equal(tokens.refresh_token, 'mock-refresh-token-raw');
      assert.equal(tokens.expires_in, 3600);
    });

    it('issues refresh token with the user identity from the auth-code record', async () => {
      await provider.exchangeAuthorizationCode(MOCK_CLIENT, 'some-auth-code');
      const issueCalls = asMock(refreshTokenStore.issue).mock.calls;
      assert.equal(issueCalls.length, 1);
      const issuedWith = issueCalls[0].arguments[0] as any;
      assert.equal(issuedWith.userId, 'google-user-123');
      assert.equal(issuedWith.email, 'user@relevantsearch.com');
      assert.deepEqual(issuedWith.scopes, TEST_SCOPES);
    });
  });

  describe('revokeToken', () => {
    it('revokes the chain when given a valid refresh token', async () => {
      // JWT-first ordering: verifyAllowExpired must throw before refresh-token path runs.
      asMock((jwt as unknown as { verifyAllowExpired: unknown }).verifyAllowExpired).mock.mockImplementation(
        async () => { throw new Error('not a jwt'); },
      );
      asMock(refreshTokenStore.validate).mock.mockImplementation(async () => ({
        user_id: 'u1', email: 'e1', scopes: TEST_SCOPES,
        chain_id: 'chain-x', created_at: new Date(),
        expires_at: new Date(Date.now() + 1000), status: 'active', rotated_at: null,
      }));
      await provider.revokeToken!(MOCK_CLIENT, { token: 'r-1' });
      const chainCalls = asMock(refreshTokenStore.revokeChain).mock.calls;
      assert.equal(chainCalls.length, 1);
      assert.equal(chainCalls[0].arguments[0], 'chain-x');
    });

    it('revokes by user when given a valid access token (JWT)', async () => {
      asMock(refreshTokenStore.validate).mock.mockImplementation(async () => null);
      asMock((jwt as unknown as { verifyAllowExpired: unknown }).verifyAllowExpired).mock.mockImplementation(
        async () => ({
          sub: 'user-jwt', email: 'e@x', scope: TEST_SCOPES.join(' '),
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      );
      await provider.revokeToken!(MOCK_CLIENT, { token: 'jwt-token' });
      const userCalls = asMock(refreshTokenStore.revokeUser).mock.calls;
      assert.equal(userCalls.length, 1);
      assert.equal(userCalls[0].arguments[0], 'user-jwt');
    });

    it('revokes by user when given an expired-but-valid JWT', async () => {
      asMock((jwt as unknown as { verifyAllowExpired: unknown }).verifyAllowExpired).mock.mockImplementation(
        async () => ({
          sub: 'expired-user',
          email: 'e@x',
          scope: TEST_SCOPES.join(' '),
          exp: Math.floor(Date.now() / 1000) - 3600, // expired 1h ago
        }),
      );
      asMock(refreshTokenStore.validate).mock.mockImplementation(async () => null);
      await provider.revokeToken!(MOCK_CLIENT, { token: 'expired-jwt' });
      const userCalls = asMock(refreshTokenStore.revokeUser).mock.calls;
      assert.equal(userCalls.length, 1);
      assert.equal(userCalls[0].arguments[0], 'expired-user');
    });

    it('returns silently when token is unknown (RFC 7009)', async () => {
      asMock(refreshTokenStore.validate).mock.mockImplementation(async () => null);
      asMock((jwt as unknown as { verifyAllowExpired: unknown }).verifyAllowExpired).mock.mockImplementation(
        async () => { throw new Error('invalid'); },
      );
      await provider.revokeToken!(MOCK_CLIENT, { token: 'garbage' });
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
