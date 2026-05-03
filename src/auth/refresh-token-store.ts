/**
 * Firestore-backed refresh-token store for the AS hop of the Drive MCP.
 *
 * Tokens are 32-byte cryptographically random values, base64url-encoded.
 * Raw tokens are returned to the client once and never persisted; Firestore
 * stores the SHA-256 hash as the document ID. Rotation is atomic via
 * db.runTransaction. Reuse of a rotated token revokes the entire chain.
 */

import { Firestore, Timestamp } from '@google-cloud/firestore';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
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
  expiresAt: Date;
}

function hashToken(rawToken: string): string {
  return createHash('sha256').update(rawToken).digest('base64url');
}

function generateRawToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Coerces a value that may be a Firestore Timestamp, a Date, or null/undefined
 * into a Date (or null). Real Firestore reads return Timestamp instances; tests
 * often pass plain Dates; this normalises both so callers can always rely on
 * Date semantics (e.g. `.getTime()`).
 */
function toDate(v: Date | Timestamp | null | undefined): Date | null {
  if (v == null) return null;
  if (v instanceof Date) return v;
  if (typeof (v as { toDate?: () => Date }).toDate === 'function') {
    return (v as { toDate: () => Date }).toDate();
  }
  return null;
}

/**
 * Normalises a raw Firestore document into a RefreshTokenRecord with Date
 * fields, regardless of whether the source returned Timestamps or Dates.
 */
function normalizeRecord(raw: FirebaseFirestore.DocumentData): RefreshTokenRecord {
  return {
    user_id: raw.user_id,
    email: raw.email,
    scopes: raw.scopes,
    chain_id: raw.chain_id,
    created_at: toDate(raw.created_at) ?? new Date(0),
    expires_at: toDate(raw.expires_at) ?? new Date(0),
    status: raw.status,
    rotated_at: toDate(raw.rotated_at),
  };
}

export class RefreshTokenStore {
  constructor(private readonly db: Firestore) {}

  async issue(params: IssueParams): Promise<IssueResult> {
    const rawToken = generateRawToken();
    const chainId = randomUUID();
    const now = Date.now();
    const expiresAt = new Date(now + CHAIN_TTL_MS);
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
    await this.db.collection(COLLECTION).doc(hashToken(rawToken)).create(record);
    return { rawToken, chainId, expiresAt };
  }

  /**
   * Reads the record by raw token. Returns null if not found.
   * Does NOT enforce expiry or status; caller branches on those fields.
   */
  async validate(rawToken: string): Promise<RefreshTokenRecord | null> {
    const snap = await this.db.collection(COLLECTION).doc(hashToken(rawToken)).get();
    if (!snap.exists) return null;
    const data = snap.data();
    if (!data) return null;
    return normalizeRecord(data);
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
        throw new InvalidGrantError('Refresh token not found');
      }
      const oldData = oldSnap.data();
      if (!oldData) {
        throw new InvalidGrantError('Refresh token not found');
      }
      const oldRecord = normalizeRecord(oldData);
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

  /**
   * Revokes every doc sharing the given chain_id. Used on reuse detection
   * and explicit revocation by refresh-token.
   *
   * Uses a single-field `where('chain_id', '==', x)` query (auto-indexed by
   * Firestore) and filters out already-revoked docs in memory. We deliberately
   * avoid a compound `where('status', 'in', [...])` because that would require
   * a composite index, which is an infra change. Chain fanouts are small (one
   * chain has at most a handful of rotated docs), so in-memory filtering is
   * trivial.
   *
   * Atomic via db.batch (up to 500 writes per batch).
   */
  async revokeChain(chainId: string): Promise<void> {
    const snap = await this.db
      .collection(COLLECTION)
      .where('chain_id', '==', chainId)
      .get();
    const targets = snap.docs.filter((d) => {
      const data = d.data();
      return data && data.status !== 'revoked';
    });
    if (targets.length === 0) return;
    // Firestore batches commit up to 500 writes atomically; chunk for safety.
    for (let i = 0; i < targets.length; i += 500) {
      const batch = this.db.batch();
      for (const d of targets.slice(i, i + 500)) {
        batch.update(d.ref, { status: 'revoked' as RefreshTokenStatus });
      }
      await batch.commit();
    }
  }

  /**
   * Revokes every chain belonging to a user. Used by revokeToken when the
   * presented token is an access JWT (not a refresh token).
   *
   * Uses a single-field `where('user_id', '==', x)` query (auto-indexed by
   * Firestore) and filters out already-revoked docs in memory. We deliberately
   * avoid a compound `where('status', 'in', [...])` because that would require
   * a composite index. User fanouts are small (a handful of chains per user).
   *
   * Atomic via db.batch (up to 500 writes per batch).
   */
  async revokeUser(userId: string): Promise<void> {
    const snap = await this.db
      .collection(COLLECTION)
      .where('user_id', '==', userId)
      .get();
    const targets = snap.docs.filter((d) => {
      const data = d.data();
      return data && data.status !== 'revoked';
    });
    if (targets.length === 0) return;
    // Firestore batches commit up to 500 writes atomically; chunk for safety.
    for (let i = 0; i < targets.length; i += 500) {
      const batch = this.db.batch();
      for (const d of targets.slice(i, i + 500)) {
        batch.update(d.ref, { status: 'revoked' as RefreshTokenStatus });
      }
      await batch.commit();
    }
  }
}
