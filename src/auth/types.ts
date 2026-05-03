/**
 * Internal auth store interfaces.
 *
 * NOTE: OAuthClient.client_secret is stored as PLAINTEXT.
 * The MCP SDK's authenticateClient does a direct string comparison —
 * hashing would break authentication.
 */

/** Persisted in Firestore `oauth_clients` collection. */
export interface OAuthClient {
  client_id: string;
  /** Plaintext — SDK does direct comparison. Do NOT hash. */
  client_secret: string;
  redirect_uris: string[];
  client_name?: string;
  created_at: Date;
}

/** Persisted in Firestore `user_tokens` collection (keyed by cerebroId or Google sub). */
export interface UserTokens {
  user_id: string;
  google_access_token: string;
  google_refresh_token: string;
  google_token_expires_at: number; // epoch seconds
  email: string;
  updated_at: Date;
}

/** Persisted in Firestore `pending_authorizations` collection (keyed by Google state). */
export interface PendingAuthorization {
  claude_state: string;
  claude_code_challenge: string;
  claude_redirect_uri: string;
  claude_client_id: string;
  google_pkce_verifier: string;
  created_at: Date;
}

/** Persisted in Firestore `authorization_codes` collection (keyed by code). */
export interface AuthCodeRecord {
  claude_code_challenge: string;
  user_id: string;
  email: string;
  google_access_token: string;
  google_refresh_token: string;
  google_token_expires_at: number; // epoch seconds
  created_at: Date;
}

/** User identity extracted from a verified JWT — available in tool handlers. */
export interface UserContext {
  sub: string;
  email: string;
  scope: string;
}

/** Lifecycle state of a refresh-token document. */
export type RefreshTokenStatus = 'active' | 'rotated' | 'revoked';

/** Persisted in Firestore `refresh_tokens` collection (keyed by SHA-256 hash of raw token). */
export interface RefreshTokenRecord {
  user_id: string;
  email: string;
  scopes: string[];
  /** UUIDv4 shared across all rotations of one logical session. */
  chain_id: string;
  created_at: Date;
  /** Chain TTL, copied verbatim to all rotations. Epoch ms. */
  expires_at: number;
  status: RefreshTokenStatus;
  rotated_at: Date | null;
}
