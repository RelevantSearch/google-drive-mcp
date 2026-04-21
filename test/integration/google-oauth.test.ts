import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { GoogleOAuth, InvalidGrantError } from '../../src/auth/google-oauth.js';

const CONFIG = {
  clientId: 'test-client-id',
  clientSecret: 'test-client-secret',
  redirectUri: 'http://localhost:3000/oauth/callback',
};

/** Helper to mock globalThis.fetch and return the mock for assertions. */
function mockFetch(response: { status: number; body: unknown }) {
  const fn = mock.fn(async () =>
    new Response(JSON.stringify(response.body), {
      status: response.status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
  globalThis.fetch = fn as unknown as typeof fetch;
  return fn;
}

describe('GoogleOAuth', () => {
  let oauth: GoogleOAuth;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    oauth = new GoogleOAuth(CONFIG);
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('authorizationUrl', () => {
    it('builds a URL with all required parameters', () => {
      const url = oauth.authorizationUrl(
        'state-123',
        'challenge-abc',
        ['openid', 'email', 'https://www.googleapis.com/auth/drive'],
      );
      const parsed = new URL(url);
      assert.equal(parsed.origin + parsed.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
      assert.equal(parsed.searchParams.get('client_id'), CONFIG.clientId);
      assert.equal(parsed.searchParams.get('redirect_uri'), CONFIG.redirectUri);
      assert.equal(parsed.searchParams.get('response_type'), 'code');
      assert.equal(parsed.searchParams.get('state'), 'state-123');
      assert.equal(parsed.searchParams.get('code_challenge'), 'challenge-abc');
      assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
      assert.equal(parsed.searchParams.get('access_type'), 'offline');
      assert.equal(parsed.searchParams.get('prompt'), 'consent');
      assert.ok(parsed.searchParams.get('scope')!.includes('openid'));
      assert.ok(parsed.searchParams.get('scope')!.includes('https://www.googleapis.com/auth/drive'));
    });
  });

  describe('exchangeCode', () => {
    it('exchanges authorization code for tokens', async () => {
      const fetchMock = mockFetch({
        status: 200,
        body: {
          access_token: 'google-access-token',
          refresh_token: 'google-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'openid email',
        },
      });

      const result = await oauth.exchangeCode('auth-code-123', 'verifier-abc');
      assert.equal(result.access_token, 'google-access-token');
      assert.equal(result.refresh_token, 'google-refresh-token');
      assert.equal(result.expires_in, 3600);
      assert.equal(result.token_type, 'Bearer');

      // Verify fetch was called with correct params
      assert.equal(fetchMock.mock.callCount(), 1);
      const [url, options] = fetchMock.mock.calls[0].arguments as unknown as [string, RequestInit];
      assert.equal(url, 'https://oauth2.googleapis.com/token');
      assert.equal(options.method, 'POST');
      const body = options.body as string;
      assert.ok(body.includes('grant_type=authorization_code'));
      assert.ok(body.includes('code=auth-code-123'));
      assert.ok(body.includes('code_verifier=verifier-abc'));
    });

    it('throws InvalidGrantError on invalid_grant response', async () => {
      mockFetch({
        status: 400,
        body: {
          error: 'invalid_grant',
          error_description: 'Code has expired',
        },
      });

      await assert.rejects(
        () => oauth.exchangeCode('expired-code', 'verifier'),
        (err: Error) => {
          assert.ok(err instanceof InvalidGrantError);
          assert.ok(err.message.includes('Code has expired'));
          return true;
        },
      );
    });

    it('throws generic error on other failures', async () => {
      mockFetch({
        status: 401,
        body: {
          error: 'invalid_client',
          error_description: 'Unknown client',
        },
      });

      await assert.rejects(
        () => oauth.exchangeCode('code', 'verifier'),
        (err: Error) => {
          assert.ok(!(err instanceof InvalidGrantError));
          assert.ok(err.message.includes('invalid_client'));
          return true;
        },
      );
    });
  });

  describe('refreshAccessToken', () => {
    it('refreshes access token using refresh token', async () => {
      const fetchMock = mockFetch({
        status: 200,
        body: {
          access_token: 'new-access-token',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'openid email',
        },
      });

      const result = await oauth.refreshAccessToken('my-refresh-token');
      assert.equal(result.access_token, 'new-access-token');
      assert.equal(result.expires_in, 3600);

      // Verify refresh_token was sent
      const [, options] = fetchMock.mock.calls[0].arguments as unknown as [string, RequestInit];
      const body = options.body as string;
      assert.ok(body.includes('grant_type=refresh_token'));
      assert.ok(body.includes('refresh_token=my-refresh-token'));
    });

    it('throws InvalidGrantError when refresh token is revoked', async () => {
      mockFetch({
        status: 400,
        body: {
          error: 'invalid_grant',
          error_description: 'Token has been revoked',
        },
      });

      await assert.rejects(
        () => oauth.refreshAccessToken('revoked-token'),
        (err: Error) => {
          assert.ok(err instanceof InvalidGrantError);
          assert.ok(err.message.includes('Token has been revoked'));
          return true;
        },
      );
    });
  });
});
