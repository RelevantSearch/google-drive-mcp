/**
 * Firestore-backed refresh-token store for the AS hop of the Drive MCP.
 *
 * Tokens are 32-byte cryptographically random values, base64url-encoded.
 * Raw tokens are returned to the client once and never persisted; Firestore
 * stores the SHA-256 hash as the document ID. Rotation is atomic via
 * db.runTransaction. Reuse of a rotated token revokes the entire chain.
 */

import { Firestore } from '@google-cloud/firestore';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { RefreshTokenRecord, RefreshTokenStatus } from './types.js';

const COLLECTION = 'refresh_tokens';
const CHAIN_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

export interface IssueParams {
  userId: string;
  email: string;
  scopes: string[];
}

export interface IssueResult {
  rawToken: string;
  chainId: string;
  expiresAt: number;
}

function hashToken(rawToken: string): string {
  return createHash('sha256').update(rawToken).digest('base64url');
}

function generateRawToken(): string {
  return randomBytes(32).toString('base64url');
}

export class RefreshTokenStore {
  constructor(private readonly db: Firestore) {}

  async issue(params: IssueParams): Promise<IssueResult> {
    const rawToken = generateRawToken();
    const chainId = randomUUID();
    const now = Date.now();
    const expiresAt = now + CHAIN_TTL_MS;
    const record: RefreshTokenRecord = {
      user_id: params.userId,
      email: params.email,
      scopes: params.scopes,
      chain_id: chainId,
      created_at: new Date(now),
      expires_at: expiresAt,
      status: 'active',
      rotated_at: null,
    };
    await this.db.collection(COLLECTION).doc(hashToken(rawToken)).set(record);
    return { rawToken, chainId, expiresAt };
  }

  /**
   * Reads the record by raw token. Returns null if not found.
   * Does NOT enforce expiry or status; caller branches on those fields.
   */
  async validate(rawToken: string): Promise<RefreshTokenRecord | null> {
    const snap = await this.db.collection(COLLECTION).doc(hashToken(rawToken)).get();
    if (!snap.exists) return null;
    return snap.data() as RefreshTokenRecord;
  }
}
