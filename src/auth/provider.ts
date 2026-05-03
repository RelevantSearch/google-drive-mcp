import type { OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Response } from 'express';
import { FirestoreStore } from './firestore-store.js';
import { GoogleOAuth } from './google-oauth.js';
import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
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

  /**
   * In-memory grace cache for OAuth 2.1 idempotent refresh-token retries
   * within `GRACE_WINDOW_MS` (5s).
   *
   * IMPORTANT: this cache is per-process. Under multi-instance Cloud Run, a
   * retry routed to a different instance will miss the cache, see the token
   * as `rotated` in Firestore, and revoke the entire chain (false-positive
   * reuse detection). The `drive-mcp` Cloud Run service is constrained to
   * `max-instances=1` (rs_infra terraform module) to avoid this. If that
   * constraint is relaxed, switch to a shared cache (Firestore short-TTL doc
   * or Memorystore) BEFORE scaling out.
   */
  private readonly graceCache = new Map<string, { tokens: OAuthTokens; expiresAt: number }>();

  /**
   * @param refreshTokenStore - Optional during Phase-2 transition. When
   *   omitted, the provider degrades to access-token-only mode:
   *   `exchangeAuthorizationCode` returns no refresh_token,
   *   `exchangeRefreshToken` throws, and `revokeToken` is a no-op for
   *   refresh tokens. Phase 3 will make this required and remove the
   *   degraded mode.
   * @deprecated Optional only during Phase 2; will become required in Phase 3.
   */
  constructor(
    private readonly store: FirestoreStore,
    private readonly googleOAuth: GoogleOAuth,
    private readonly jwt: McpJwt,
    private readonly publicUrl: string,
    private readonly scopes: string[],
    private readonly refreshTokenStore?: RefreshTokenStore,
  ) {
    if (!refreshTokenStore) {
      console.warn(
        'DriveOAuthProvider: refreshTokenStore not provided - refresh tokens disabled (Phase 2 degraded mode)',
      );
    }
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
    if (!record) throw new InvalidGrantError('Refresh token not found');
    if (record.status === 'revoked') throw new InvalidGrantError('Refresh token revoked');
    if (record.expires_at.getTime() < Date.now()) {
      throw new InvalidGrantError('Refresh token expired');
    }
    if (record.status === 'rotated') {
      await this.refreshTokenStore.revokeChain(record.chain_id);
      throw new InvalidGrantError('Refresh token reuse detected');
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
    // Schedule eviction so unaccessed entries don't accumulate.
    // unref() so a pending timer doesn't block process shutdown.
    const timer = setTimeout(() => this.graceCache.delete(refreshToken), GRACE_WINDOW_MS);
    timer.unref();
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

  /**
   * RFC 7009 token revocation. Accepts both refresh and access tokens.
   * Returns silently for unknown tokens (no information leak).
   */
  async revokeToken(
    _client: OAuthClientInformationFull,
    request: { token: string; token_type_hint?: string },
  ): Promise<void> {
    if (!this.refreshTokenStore) {
      return;
    }
    // Try access-token (JWT) path first - in-process HMAC verify is sub-ms,
    // a Firestore validate() round-trip is 10-50ms. Use verifyAllowExpired
    // so an expired-but-validly-signed JWT still revokes its refresh chain
    // per RFC 7009 §2.2.
    try {
      const payload = await this.jwt.verifyAllowExpired(request.token);
      await this.refreshTokenStore.revokeUser(payload.sub);
      return;
    } catch {
      // Not our JWT (or invalid sig) - try refresh-token path
    }
    const record = await this.refreshTokenStore.validate(request.token);
    if (record) {
      await this.refreshTokenStore.revokeChain(record.chain_id);
    }
    // If neither matches, return silently per RFC 7009
  }
}
