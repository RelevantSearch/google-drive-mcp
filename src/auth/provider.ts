import type { OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Response } from 'express';
import { FirestoreStore } from './firestore-store.js';
import { GoogleOAuth, InvalidGrantError } from './google-oauth.js';
import { McpJwt } from './jwt.js';
import type { RefreshTokenStore } from './refresh-token-store.js';
import { createHash, randomBytes } from 'crypto';

/**
 * Authorization codes are short-lived by RFC 6749 §4.1.2 (recommended 10 min
 * max). We enforce 60s to reduce the replay window if a code leaks between
 * issuance and /token consumption.
 */
export const AUTH_CODE_MAX_AGE_MS = 60_000;

/**
 * Idempotency window for refresh-token retries. If the same raw token is
 * presented twice within this window (e.g. client retried after a transient
 * network error), return the same token pair instead of triggering reuse
 * detection.
 */
const GRACE_WINDOW_MS = 5_000;

export class DriveOAuthProvider implements OAuthServerProvider {
  // Must be a getter per SDK interface
  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  private _clientsStore: OAuthRegisteredClientsStore;

  private readonly graceCache = new Map<string, { tokens: OAuthTokens; expiresAt: number }>();

  constructor(
    private readonly store: FirestoreStore,
    private readonly googleOAuth: GoogleOAuth,
    private readonly jwt: McpJwt,
    private readonly publicUrl: string,
    private readonly scopes: string[],
    // Optional in Phase 2 only so Phase-3-territory call sites (src/index.ts,
    // e2e-oauth-flow.test.ts) still compile. Phase 3 will make it required.
    private readonly refreshTokenStore?: RefreshTokenStore,
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

    const age = Date.now() - new Date(record.created_at).getTime();
    if (age > AUTH_CODE_MAX_AGE_MS) {
      throw new Error('Invalid or expired authorization code');
    }

    const accessToken = await this.jwt.sign({
      sub: record.user_id,
      email: record.email,
      scope: this.scopes.join(' '),
    });

    const refresh = this.refreshTokenStore
      ? await this.refreshTokenStore.issue({
          userId: record.user_id,
          email: record.email,
          scopes: this.scopes,
        })
      : undefined;

    // Return snake_case OAuthTokens per RFC
    return {
      access_token: accessToken,
      ...(refresh ? { refresh_token: refresh.rawToken } : {}),
      token_type: 'bearer',
      expires_in: 3600,
      scope: this.scopes.join(' '),
    };
  }

  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    _resource?: URL,
  ): Promise<OAuthTokens> {
    if (!this.refreshTokenStore) {
      throw new Error('Refresh tokens not supported');
    }

    // Idempotent retry within grace window: same raw token returns the same
    // pair we minted on the first call, avoiding spurious reuse-detection.
    const cached = this.graceCache.get(refreshToken);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.tokens;
    }
    if (cached) this.graceCache.delete(refreshToken);

    const record = await this.refreshTokenStore.validate(refreshToken);
    if (!record) throw new InvalidGrantError('invalid_grant');
    if (record.status === 'revoked') throw new InvalidGrantError('invalid_grant');
    if (record.expires_at.getTime() < Date.now()) {
      throw new InvalidGrantError('invalid_grant');
    }
    if (record.status === 'rotated') {
      await this.refreshTokenStore.revokeChain(record.chain_id);
      throw new InvalidGrantError('invalid_grant');
    }

    const newRefresh = await this.refreshTokenStore.rotate(refreshToken);
    const accessToken = await this.jwt.sign({
      sub: record.user_id,
      email: record.email,
      scope: record.scopes.join(' '),
    });

    const tokens: OAuthTokens = {
      access_token: accessToken,
      refresh_token: newRefresh.rawToken,
      token_type: 'bearer',
      expires_in: 3600,
      scope: record.scopes.join(' '),
    };
    this.graceCache.set(refreshToken, {
      tokens,
      expiresAt: Date.now() + GRACE_WINDOW_MS,
    });
    return tokens;
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
