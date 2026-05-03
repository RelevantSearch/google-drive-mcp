import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { RefreshTokenStore } from '../../src/auth/refresh-token-store.js';
import type { Firestore } from '@google-cloud/firestore';
import type { RefreshTokenRecord } from '../../src/auth/types.js';

function makeMockFirestore() {
  const docs = new Map<string, any>();

  const makeDocRef = (collection: string, docId: string) => {
    const path = `${collection}/${docId}`;
    return {
      _path: path,
      _get: () => ({ exists: docs.has(path), data: () => docs.get(path) }),
      _set: (data: any) => docs.set(path, data),
      _update: (patch: any) => docs.set(path, { ...(docs.get(path) || {}), ...patch }),
      _delete: () => docs.delete(path),
      get: mock.fn(async () => ({ exists: docs.has(path), data: () => docs.get(path) })),
      set: mock.fn(async (data: any) => { docs.set(path, data); }),
      update: mock.fn(async (patch: any) => { docs.set(path, { ...(docs.get(path) || {}), ...patch }); }),
      delete: mock.fn(async () => { docs.delete(path); }),
    };
  };

  const db = {
    collection: mock.fn((collection: string) => ({
      doc: mock.fn((docId: string) => makeDocRef(collection, docId)),
      where: mock.fn((field: string, _op: string, value: unknown) => ({
        get: mock.fn(async () => ({
          docs: Array.from(docs.entries())
            .filter(([p]) => p.startsWith(`${collection}/`))
            .filter(([, d]) => d && d[field] === value)
            .map(([p, d]) => ({ ref: makeDocRef(collection, p.slice(collection.length + 1)), data: () => d })),
        })),
      })),
    })),
    runTransaction: mock.fn(async (fn: any) => {
      const tx = {
        get: (ref: any) => Promise.resolve(ref._get()),
        update: (ref: any, patch: any) => ref._update(patch),
        set: (ref: any, data: any) => ref._set(data),
        delete: (ref: any) => ref._delete(),
      };
      return fn(tx);
    }),
  } as any as Firestore;

  return { db, docs };
}

describe('RefreshTokenStore', () => {
  let mocks: ReturnType<typeof makeMockFirestore>;
  let store: RefreshTokenStore;

  beforeEach(() => {
    mocks = makeMockFirestore();
    store = new RefreshTokenStore(mocks.db);
  });

  describe('issue', () => {
    it('returns a base64url raw token of at least 32 bytes', async () => {
      const result = await store.issue({
        userId: 'user-1',
        email: 'a@relevantsearch.com',
        scopes: ['drive'],
      });
      assert.match(result.rawToken, /^[A-Za-z0-9_-]{43,}$/);
      assert.equal(typeof result.chainId, 'string');
      assert.ok(result.chainId.length >= 32);
    });

    it('persists a doc keyed by SHA-256(rawToken) with status=active', async () => {
      const result = await store.issue({
        userId: 'user-1',
        email: 'a@relevantsearch.com',
        scopes: ['drive'],
      });
      const expectedDocId = createHash('sha256').update(result.rawToken).digest('base64url');
      const persisted = mocks.docs.get(`refresh_tokens/${expectedDocId}`) as RefreshTokenRecord;
      assert.ok(persisted, 'doc should be persisted');
      assert.equal(persisted.user_id, 'user-1');
      assert.equal(persisted.email, 'a@relevantsearch.com');
      assert.deepEqual(persisted.scopes, ['drive']);
      assert.equal(persisted.chain_id, result.chainId);
      assert.equal(persisted.status, 'active');
      assert.equal(persisted.rotated_at, null);
    });

    it('sets expires_at 90 days from now', async () => {
      const before = Date.now();
      const result = await store.issue({
        userId: 'user-1',
        email: 'a@relevantsearch.com',
        scopes: ['drive'],
      });
      const after = Date.now();
      const expectedMin = before + 90 * 24 * 60 * 60 * 1000;
      const expectedMax = after + 90 * 24 * 60 * 60 * 1000;
      const expectedDocId = createHash('sha256').update(result.rawToken).digest('base64url');
      const persisted = mocks.docs.get(`refresh_tokens/${expectedDocId}`) as RefreshTokenRecord;
      assert.ok(persisted.expires_at >= expectedMin);
      assert.ok(persisted.expires_at <= expectedMax);
    });
  });

  describe('validate', () => {
    it('returns the record when token is active and not expired', async () => {
      const issued = await store.issue({
        userId: 'user-1',
        email: 'a@relevantsearch.com',
        scopes: ['drive'],
      });
      const record = await store.validate(issued.rawToken);
      assert.ok(record);
      assert.equal(record.user_id, 'user-1');
      assert.equal(record.status, 'active');
    });

    it('returns null when token does not exist', async () => {
      const record = await store.validate('nonexistent-token');
      assert.equal(record, null);
    });

    it('returns the record even when status is rotated (caller decides reuse)', async () => {
      const docId = createHash('sha256').update('xyz').digest('base64url');
      const expired: RefreshTokenRecord = {
        user_id: 'u', email: 'e', scopes: ['drive'],
        chain_id: 'c', created_at: new Date(), expires_at: Date.now() + 1000,
        status: 'rotated', rotated_at: new Date(),
      };
      mocks.docs.set(`refresh_tokens/${docId}`, expired);
      const record = await store.validate('xyz');
      assert.equal(record?.status, 'rotated');
    });

    it('returns the record even when expired (caller decides expiry)', async () => {
      const docId = createHash('sha256').update('past').digest('base64url');
      const expired: RefreshTokenRecord = {
        user_id: 'u', email: 'e', scopes: ['drive'],
        chain_id: 'c', created_at: new Date(), expires_at: Date.now() - 1000,
        status: 'active', rotated_at: null,
      };
      mocks.docs.set(`refresh_tokens/${docId}`, expired);
      const record = await store.validate('past');
      assert.equal(record?.status, 'active');
      assert.ok(record!.expires_at < Date.now());
    });
  });

  describe('rotate', () => {
    it('atomically marks old as rotated and writes new active doc with same chainId and expiresAt', async () => {
      const issued = await store.issue({
        userId: 'user-1',
        email: 'a@relevantsearch.com',
        scopes: ['drive'],
      });
      const oldDocId = createHash('sha256').update(issued.rawToken).digest('base64url');
      const oldRecord = mocks.docs.get(`refresh_tokens/${oldDocId}`) as RefreshTokenRecord;

      const rotated = await store.rotate(issued.rawToken);
      assert.notEqual(rotated.rawToken, issued.rawToken);
      assert.equal(rotated.chainId, issued.chainId);
      assert.equal(rotated.expiresAt, issued.expiresAt);

      const oldNow = mocks.docs.get(`refresh_tokens/${oldDocId}`) as RefreshTokenRecord;
      assert.equal(oldNow.status, 'rotated');
      assert.ok(oldNow.rotated_at instanceof Date);

      const newDocId = createHash('sha256').update(rotated.rawToken).digest('base64url');
      const newRecord = mocks.docs.get(`refresh_tokens/${newDocId}`) as RefreshTokenRecord;
      assert.equal(newRecord.status, 'active');
      assert.equal(newRecord.chain_id, oldRecord.chain_id);
      assert.equal(newRecord.expires_at, oldRecord.expires_at);
    });

    it('throws when raw token is unknown', async () => {
      await assert.rejects(() => store.rotate('unknown-token'), /not found/i);
    });
  });

  describe('revokeChain', () => {
    it('marks all docs sharing chainId as revoked', async () => {
      const a = await store.issue({ userId: 'u1', email: 'e1', scopes: ['drive'] });
      const b = await store.rotate(a.rawToken);
      const c = await store.rotate(b.rawToken);
      await store.revokeChain(a.chainId);
      for (const raw of [a.rawToken, b.rawToken, c.rawToken]) {
        const docId = createHash('sha256').update(raw).digest('base64url');
        const record = mocks.docs.get(`refresh_tokens/${docId}`) as RefreshTokenRecord;
        assert.equal(record.status, 'revoked', `expected ${raw.slice(0,6)} revoked`);
      }
    });

    it('is a no-op when no docs match the chainId', async () => {
      await store.revokeChain('nonexistent-chain');
    });
  });

  describe('revokeUser', () => {
    it('marks all docs for a user as revoked across multiple chains', async () => {
      const chain1a = await store.issue({ userId: 'u1', email: 'e1', scopes: ['drive'] });
      const chain1b = await store.rotate(chain1a.rawToken);
      const chain2 = await store.issue({ userId: 'u1', email: 'e1', scopes: ['drive'] });
      const otherUser = await store.issue({ userId: 'u2', email: 'e2', scopes: ['drive'] });

      await store.revokeUser('u1');

      for (const raw of [chain1a.rawToken, chain1b.rawToken, chain2.rawToken]) {
        const docId = createHash('sha256').update(raw).digest('base64url');
        const record = mocks.docs.get(`refresh_tokens/${docId}`) as RefreshTokenRecord;
        assert.equal(record.status, 'revoked');
      }
      const otherDocId = createHash('sha256').update(otherUser.rawToken).digest('base64url');
      const otherRecord = mocks.docs.get(`refresh_tokens/${otherDocId}`) as RefreshTokenRecord;
      assert.equal(otherRecord.status, 'active');
    });
  });
});
