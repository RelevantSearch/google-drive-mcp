/**
 * In-memory token cache with 10-minute TTL.
 * Keyed by user ID. Cleared on InvalidGrantError to evict stale entries.
 */

const TEN_MINUTES_MS = 10 * 60 * 1000;

interface CacheEntry {
  token: string;
  expiresAt: number; // epoch ms
}

const cache = new Map<string, CacheEntry>();

/**
 * Returns a cached Google access token if it exists and hasn't expired.
 * Returns undefined on miss or expiry (expired entries are evicted).
 */
export function getCachedToken(userId: string): string | undefined {
  const entry = cache.get(userId);
  if (!entry) return undefined;
  if (Date.now() >= entry.expiresAt) {
    cache.delete(userId);
    return undefined;
  }
  return entry.token;
}

/**
 * Stores a Google access token with a 10-minute TTL.
 */
export function setCachedToken(userId: string, token: string): void {
  cache.set(userId, {
    token,
    expiresAt: Date.now() + TEN_MINUTES_MS,
  });
}

/**
 * Removes a cached token — called on InvalidGrantError to clear stale entries.
 */
export function deleteCachedToken(userId: string): void {
  cache.delete(userId);
}
