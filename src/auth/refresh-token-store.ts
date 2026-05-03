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

  /**
   * Atomically rotates the token: marks the existing doc as rotated and
   * writes a new active doc with the same chain_id and expires_at.
   * Throws if the rawToken does not resolve to an existing doc.
   * Caller is responsible for status/expiry validation BEFORE calling rotate.
   */
  async rotate(rawToken: string): Promise<IssueResult> {
    const oldHash = hashToken(rawToken);
    const newRawToken = generateRawToken();
    const newHash = hashToken(newRawToken);

    return this.db.runTransaction(async (tx) => {
      const oldRef = this.db.collection(COLLECTION).doc(oldHash);
      const oldSnap = await tx.get(oldRef);
      if (!oldSnap.exists) {
        throw new Error('Refresh token not found');
      }
      const oldRecord = oldSnap.data() as RefreshTokenRecord;
      const newRef = this.db.collection(COLLECTION).doc(newHash);
      const now = new Date();

      tx.update(oldRef, { status: 'rotated' as RefreshTokenStatus, rotated_at: now });
      const newRecord: RefreshTokenRecord = {
        user_id: oldRecord.user_id,
        email: oldRecord.email,
        scopes: oldRecord.scopes,
        chain_id: oldRecord.chain_id,
        created_at: now,
        expires_at: oldRecord.expires_at,
        status: 'active',
        rotated_at: null,
      };
      tx.set(newRef, newRecord);

      return {
        rawToken: newRawToken,
        chainId: oldRecord.chain_id,
        expiresAt: oldRecord.expires_at,
      };
    });
  }
}
