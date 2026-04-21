/**
 * Resolves a fresh Google access token for a user.
 *
 * Order of operations:
 *   1. In-memory cache (10-min TTL) — cheap and dominates.
 *   2. Firestore `user_tokens` — stored access_token if still valid.
 *   3. Google refresh — mint a new access token from the refresh token.
 *
 * On `invalid_grant` from Google (refresh revoked/expired) the cached entry
 * is evicted so the next call forces a clean re-fetch from Firestore. The
 * caller is expected to propagate the error; claude.ai will restart the
 * connector flow.
 */

import type { FirestoreStore } from './firestore-store.js';
import { GoogleOAuth, InvalidGrantError } from './google-oauth.js';
import {
  getCachedToken,
  setCachedToken,
  deleteCachedToken,
} from './token-cache.js';

const NOW_SEC = () => Math.floor(Date.now() / 1000);
const EARLY_REFRESH_SEC = 60; // refresh 60s before Google's stated expiry

export async function getUserAccessToken(
  userId: string,
  store: FirestoreStore,
  googleOAuth: GoogleOAuth,
): Promise<string> {
  const cached = getCachedToken(userId);
  if (cached) return cached;

  const tokens = await store.getUserTokens(userId);
  if (!tokens) {
    throw new Error(`No Google tokens stored for user ${userId}`);
  }

  const nowSec = NOW_SEC();
  if (tokens.google_token_expires_at - EARLY_REFRESH_SEC > nowSec) {
    setCachedToken(userId, tokens.google_access_token);
    return tokens.google_access_token;
  }

  try {
    const refreshed = await googleOAuth.refreshAccessToken(
      tokens.google_refresh_token,
    );
    const newExpiry = NOW_SEC() + refreshed.expires_in;
    await store.saveUserTokens({
      ...tokens,
      google_access_token: refreshed.access_token,
      google_token_expires_at: newExpiry,
      updated_at: new Date(),
    });
    setCachedToken(userId, refreshed.access_token);
    return refreshed.access_token;
  } catch (err) {
    if (err instanceof InvalidGrantError) {
      deleteCachedToken(userId);
    }
    throw err;
  }
}
