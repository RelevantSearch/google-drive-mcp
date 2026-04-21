/**
 * Fetch-based Google OAuth 2.0 helpers.
 *
 * Uses native `fetch` — no googleapis dependency.
 * Handles authorization URL building, code exchange, and token refresh.
 */

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';

export class InvalidGrantError extends Error {
  constructor(message = 'invalid_grant') {
    super(message);
    this.name = 'InvalidGrantError';
  }
}

export interface GoogleTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  scope?: string;
  id_token?: string;
}

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export class GoogleOAuth {
  constructor(private readonly config: GoogleOAuthConfig) {}

  /**
   * Builds a Google authorization URL with PKCE (S256) and offline access.
   */
  authorizationUrl(
    state: string,
    codeChallenge: string,
    scopes: string[],
  ): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: scopes.join(' '),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      access_type: 'offline',
      prompt: 'consent',
    });
    return `${GOOGLE_AUTH_URL}?${params.toString()}`;
  }

  /**
   * Exchanges an authorization code for tokens.
   * Throws InvalidGrantError on `invalid_grant` response.
   */
  async exchangeCode(
    code: string,
    codeVerifier: string,
  ): Promise<GoogleTokenResponse> {
    const body = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      code_verifier: codeVerifier,
      grant_type: 'authorization_code',
      redirect_uri: this.config.redirectUri,
    });

    const res = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await res.json();

    if (!res.ok) {
      if (data.error === 'invalid_grant') {
        throw new InvalidGrantError(data.error_description || 'invalid_grant');
      }
      throw new Error(
        `Google token exchange failed: ${data.error} — ${data.error_description}`,
      );
    }

    return data as GoogleTokenResponse;
  }

  /**
   * Refreshes an access token using a refresh token.
   * Throws InvalidGrantError if the refresh token is revoked/expired.
   */
  async refreshAccessToken(
    refreshToken: string,
  ): Promise<GoogleTokenResponse> {
    const body = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    });

    const res = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const data = await res.json();

    if (!res.ok) {
      if (data.error === 'invalid_grant') {
        throw new InvalidGrantError(data.error_description || 'invalid_grant');
      }
      throw new Error(
        `Google token refresh failed: ${data.error} — ${data.error_description}`,
      );
    }

    return data as GoogleTokenResponse;
  }
}
