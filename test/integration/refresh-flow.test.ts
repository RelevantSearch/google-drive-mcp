import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { DriveOAuthProvider } from '../../src/auth/provider.js';
import type { FirestoreStore } from '../../src/auth/firestore-store.js';
import type { GoogleOAuth } from '../../src/auth/google-oauth.js';
import type { McpJwt } from '../../src/auth/jwt.js';
import type { RefreshTokenRecord } from '../../src/auth/types.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const TEST_SCOPES = ['openid', 'email', 'https://www.googleapis.com/auth/drive'];
const PUBLIC_URL = 'https://drive-mcp.example.com';
const MOCK_CLIENT: OAuthClientInformationFull = {
  client_id: 'cid', client_secret: 'cs', redirect_uris: ['https://claude.ai/cb'],
} as OAuthClientInformationFull;

function activeRecord(overrides: Partial<RefreshTokenRecord> = {}): RefreshTokenRecord {
  return {
    user_id: 'u1',
    email: 'u1@relevantsearch.com',
    scopes: TEST_SCOPES,
    chain_id: 'chain-1',
    created_at: new Date(),
    expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    status: 'active',
    rotated_at: null,
    ...overrides,
  };
}

function makeMocks() {
  const store = {
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

  const googleOAuth = {
    authorizationUrl: mock.fn(() => 'https://accounts.google.com/?mock=1'),
    exchangeCode: mock.fn(async () => ({})),
    refreshAccessToken: mock.fn(async () => ({})),
  } as unknown as GoogleOAuth;

  const jwt = {
    sign: mock.fn(async () => 'jwt-' + Math.random().toString(36).slice(2, 8)),
    verify: mock.fn(async () => ({ sub: 'u1', email: 'u1@relevantsearch.com', scope: TEST_SCOPES.join(' '), exp: 0 })),
  } as unknown as McpJwt;

  const refreshTokenStore = {
    issue: mock.fn(async () => ({ rawToken: 'r-init', chainId: 'chain-1', expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) })),
    validate: mock.fn(async () => null as RefreshTokenRecord | null),
    rotate: mock.fn(async () => ({ rawToken: 'r-new', chainId: 'chain-1', expiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000) })),
    revokeChain: mock.fn(async () => {}),
    revokeUser: mock.fn(async () => {}),
  };

  return { store, googleOAuth, jwt, refreshTokenStore };
}

describe('exchangeRefreshToken', () => {
  let mocks: ReturnType<typeof makeMocks>;
  let provider: DriveOAuthProvider;

  beforeEach(() => {
    mocks = makeMocks();
    provider = new DriveOAuthProvider(
      mocks.store, mocks.googleOAuth, mocks.jwt,
      PUBLIC_URL, TEST_SCOPES, mocks.refreshTokenStore as any,
    );
  });

  it('happy path: validates, rotates, mints JWT, returns new pair', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => activeRecord());

    const tokens = await provider.exchangeRefreshToken(MOCK_CLIENT, 'r-init');
    assert.match(tokens.access_token!, /^jwt-/);
    assert.equal(tokens.refresh_token, 'r-new');
    assert.equal(tokens.expires_in, 3600);
    assert.equal((mocks.refreshTokenStore.rotate as any).mock.calls.length, 1);
    assert.equal((mocks.refreshTokenStore.revokeChain as any).mock.calls.length, 0);
  });

  it('returns invalid_grant when refresh_token is unknown', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => null);
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'unknown'),
      (err: unknown) =>
        err instanceof OAuthError && (err as { errorCode: string }).errorCode === 'invalid_grant',
    );
  });

  it('returns invalid_grant when refresh_token is revoked', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => activeRecord({ status: 'revoked' }));
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'revoked'),
      (err: unknown) =>
        err instanceof OAuthError && (err as { errorCode: string }).errorCode === 'invalid_grant',
    );
  });

  it('returns invalid_grant when refresh_token is expired', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () =>
      activeRecord({ expires_at: new Date(Date.now() - 1000) }));
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'old'),
      (err: unknown) =>
        err instanceof OAuthError && (err as { errorCode: string }).errorCode === 'invalid_grant',
    );
  });

  it('reuse detection: rotated token presented beyond grace revokes chain', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () =>
      activeRecord({ status: 'rotated', rotated_at: new Date(Date.now() - 10_000) }));
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'leaked'),
      (err: unknown) =>
        err instanceof OAuthError && (err as { errorCode: string }).errorCode === 'invalid_grant',
    );
    assert.equal((mocks.refreshTokenStore.revokeChain as any).mock.calls.length, 1);
  });

  it('grace window: same raw token within 5s returns identical pair, no chain revoke', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => activeRecord());
    const first = await provider.exchangeRefreshToken(MOCK_CLIENT, 'r-init');

    // After rotation, validate sees the now-rotated record
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () =>
      activeRecord({ status: 'rotated', rotated_at: new Date() }));

    const second = await provider.exchangeRefreshToken(MOCK_CLIENT, 'r-init');
    assert.equal(second.access_token, first.access_token);
    assert.equal(second.refresh_token, first.refresh_token);
    assert.equal((mocks.refreshTokenStore.revokeChain as any).mock.calls.length, 0);
    assert.equal((mocks.refreshTokenStore.rotate as any).mock.calls.length, 1);
  });
});
