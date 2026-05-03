---
version: 1
---

# Drive MCP refresh-token support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement OAuth 2.1 refresh-token semantics in the AS hop of the team Drive MCP server (`drive-mcp.relevantsearch.com`) so claude.ai can extend its session against our server without redoing the Google OAuth flow. Eliminates the 2-3 day forced relogin cycle.

**Architecture:** New Firestore-backed `RefreshTokenStore` issues opaque-random refresh tokens with rotate-on-use semantics, a 90-day chain TTL, reuse detection, and a 5-second idempotent-retry grace window. The AS hop never calls Google during refresh; Google access-token refresh continues to happen lazily on the tool-call path via `getUserAccessToken`. Existing `user_tokens` collection and `GoogleOAuth.refreshAccessToken` are untouched.

**Tech Stack:** TypeScript (ESM), Node 22, `@google-cloud/firestore@^8.5.0`, `jose` (JWT), `node:test` runner, MCP SDK (`@modelcontextprotocol/sdk`), Cloud Run deploy via existing `.github/workflows/deploy.yml`.

**Repo:** `RelevantSearch/google-drive-mcp` (default branch `master`). Plan docs canonical in `rs_infra`; mirror to fork at end of Phase 4.

**Design:** [./2026-05-02-drive-mcp-refresh-tokens-design.md](./2026-05-02-drive-mcp-refresh-tokens-design.md)

---

## File Structure

### Files to create (in fork)

| Path | Responsibility |
|---|---|
| `src/auth/refresh-token-store.ts` | Firestore-backed refresh-token store. Hashing, atomic rotation, chain/user revoke. ~150 LoC. |
| `test/auth/refresh-token-store.test.ts` | Unit tests for the store, mocking `Firestore` directly. ~250 LoC. |
| `test/integration/refresh-flow.test.ts` | Integration tests for the full provider refresh flow. ~200 LoC. |

### Files to modify (in fork)

| Path | What changes |
|---|---|
| `src/auth/types.ts` | Add `RefreshTokenRecord`, `TokenStatus` types. ~15 LoC. |
| `src/auth/provider.ts` | Constructor takes `RefreshTokenStore`. `exchangeAuthorizationCode` issues refresh_token. `exchangeRefreshToken` validates → rotates → mints. `revokeToken` implemented. ~80 LoC net add. |
| `src/index.ts` | Construct `RefreshTokenStore`, pass to `DriveOAuthProvider`. ~3 LoC. |
| `test/integration/oauth-provider.test.ts` | Add mock for `RefreshTokenStore`, extend tests. ~50 LoC. |
| `test/integration/e2e-oauth-flow.test.ts` | Add a refresh round-trip step at the end. ~30 LoC. |

### Files to read for context (no changes)

- `src/auth/firestore-store.ts` — pattern for Firestore CRUD, especially `consumeAuthorizationCode` (uses `db.runTransaction`)
- `src/auth/user-token.ts` — confirms Google refresh stays on this path; AS-hop never calls Google
- `src/auth/google-oauth.ts` — `refreshAccessToken` already exists, no changes
- `src/auth/jwt.ts` — `McpJwt.sign({sub, email, scope})` signature

---

## Phase 0: Setup

### Task 0.1: Worktree the fork

**Files:** none (workspace setup)

- [ ] **Step 1:** Clone the fork to your local machine (skip if already present at `~/git/RS/google-drive-mcp-team`).

```bash
gh repo clone RelevantSearch/google-drive-mcp ~/git/RS/google-drive-mcp-team
git -C ~/git/RS/google-drive-mcp-team checkout master
git -C ~/git/RS/google-drive-mcp-team pull --ff-only
```

- [ ] **Step 2:** Create the worktree on a feature branch.

```bash
git -C ~/git/RS/google-drive-mcp-team worktree add ~/git/RS/google-drive-mcp-team_feat-refresh-tokens -b feat/refresh-tokens
```

- [ ] **Step 3:** Set per-repo identity (per memory `user_identities.md`).

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens config user.email stefan@relevantsearch.com
```

- [ ] **Step 4:** Install deps in the worktree.

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens
npm ci
```

Expected: install succeeds, no audit failures that aren't already on `master`.

### Task 0.2: Run baseline tests on master

**Files:** none

- [ ] **Step 1:** Run the full test suite from the worktree (still on the feature branch with no changes; git history is identical to master).

```bash
npm test 2>&1 | tee /tmp/baseline-master.log
```

- [ ] **Step 2:** Inspect `/tmp/baseline-master.log` for any failing tests. Count pass/fail.

- [ ] **Step 3:** If failures exist, document them in a `BASELINE.md` file at the worktree root with test name + error summary. This is the pre-existing failure baseline; Phase-3 Test gate compares against it. If all green, skip this step.

- [ ] **Step 4:** Commit baseline doc only if step 3 produced one.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add BASELINE.md
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "chore: capture pre-existing test failures"
```

### Task 0.3: Create test directory structure

**Files:**
- Create: `test/auth/` (directory only)

- [ ] **Step 1:** Create the unit-test directory.

```bash
mkdir -p ~/git/RS/google-drive-mcp-team_feat-refresh-tokens/test/auth
```

- [ ] **Step 2:** Verify `tsconfig.test.json` already includes `test/**/*` (check the file).

```bash
grep -A 2 '"include"' ~/git/RS/google-drive-mcp-team_feat-refresh-tokens/tsconfig.test.json
```

Expected: glob covers `test/**/*.ts` or equivalent. If not, file an issue and stop here — fixing tsconfig is out of scope.

---

## Phase 1: RefreshTokenStore

Each task in this phase follows TDD: write failing test, run it, implement, run it green, commit.

### Task 1.1: Add types

**Files:**
- Modify: `src/auth/types.ts` (append after the existing interfaces)

- [ ] **Step 1:** Append to `src/auth/types.ts`.

```typescript
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
```

- [ ] **Step 2:** Build to verify no TS errors.

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens && npm run build
```

Expected: build succeeds.

- [ ] **Step 3:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/types.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): add RefreshTokenRecord types"
```

### Task 1.2: RefreshTokenStore.issue() — TDD

**Files:**
- Create: `test/auth/refresh-token-store.test.ts`
- Create: `src/auth/refresh-token-store.ts`

- [ ] **Step 1:** Write the failing test for `issue()`.

Create `test/auth/refresh-token-store.test.ts`:

```typescript
import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { RefreshTokenStore } from '../../src/auth/refresh-token-store.js';
import type { Firestore } from '@google-cloud/firestore';
import type { RefreshTokenRecord } from '../../src/auth/types.js';

/** Build a mock Firestore that records writes to a Map keyed by collection+docId. */
function makeMockFirestore(): { db: Firestore; writes: Map<string, any>; reads: Map<string, any> } {
  const writes = new Map<string, any>();
  const reads = new Map<string, any>();

  const docMock = (collection: string, docId: string) => ({
    set: mock.fn(async (data: any) => { writes.set(`${collection}/${docId}`, data); }),
    update: mock.fn(async (patch: any) => {
      const existing = writes.get(`${collection}/${docId}`) || {};
      writes.set(`${collection}/${docId}`, { ...existing, ...patch });
    }),
    get: mock.fn(async () => {
      const data = reads.get(`${collection}/${docId}`);
      return { exists: data !== undefined, data: () => data };
    }),
    delete: mock.fn(async () => { writes.delete(`${collection}/${docId}`); }),
  });

  const db = {
    collection: mock.fn((collection: string) => ({
      doc: mock.fn((docId: string) => docMock(collection, docId)),
    })),
    runTransaction: mock.fn(async (fn: any) => {
      // Simplified: tx.get/update/set delegate to the same docMock
      const tx = {
        get: mock.fn(async (ref: any) => {
          // ref.path-like; we use a marker on the mock
          return ref._get();
        }),
        update: mock.fn((ref: any, patch: any) => ref._update(patch)),
        set: mock.fn((ref: any, data: any) => ref._set(data)),
        delete: mock.fn((ref: any) => ref._delete()),
      };
      return fn(tx);
    }),
  } as unknown as Firestore;

  return { db, writes, reads };
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
      // base64url of 32 bytes = 43 chars (no padding)
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
      const persisted = mocks.writes.get(`refresh_tokens/${expectedDocId}`) as RefreshTokenRecord;
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
      const persisted = mocks.writes.get(`refresh_tokens/${expectedDocId}`) as RefreshTokenRecord;
      assert.ok(persisted.expires_at >= expectedMin);
      assert.ok(persisted.expires_at <= expectedMax);
    });
  });
});
```

- [ ] **Step 2:** Run the test — expect it to fail because `RefreshTokenStore` doesn't exist yet.

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens
npm run test:build
node --test .tmp-test/test/auth/refresh-token-store.test.js
```

Expected: TypeScript build error: `Cannot find module '../../src/auth/refresh-token-store.js'`.

- [ ] **Step 3:** Create the implementation file `src/auth/refresh-token-store.ts`.

```typescript
/**
 * Firestore-backed refresh-token store for the AS hop of the Drive MCP.
 *
 * Tokens are 32-byte cryptographically random values, base64url-encoded.
 * Raw tokens are returned to the client once and never persisted; Firestore
 * stores the SHA-256 hash as the document ID. Rotation is atomic via
 * `db.runTransaction`. Reuse of a rotated token revokes the entire chain.
 */

import { Firestore, Timestamp } from '@google-cloud/firestore';
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
}
```

- [ ] **Step 4:** Run the test — expect green.

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens
npm run test:build
node --test .tmp-test/test/auth/refresh-token-store.test.js
```

Expected: 3 passing tests.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/refresh-token-store.ts test/auth/refresh-token-store.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): RefreshTokenStore.issue() with hashing and 90d TTL"
```

### Task 1.3: RefreshTokenStore.validate() — TDD

**Files:**
- Modify: `test/auth/refresh-token-store.test.ts` (add `describe('validate', ...)`)
- Modify: `src/auth/refresh-token-store.ts`

- [ ] **Step 1:** Append to the test file inside the outer `describe('RefreshTokenStore', ...)`:

```typescript
  describe('validate', () => {
    it('returns the record when token is active and not expired', async () => {
      const issued = await store.issue({
        userId: 'user-1',
        email: 'a@relevantsearch.com',
        scopes: ['drive'],
      });
      // Seed reads with what was just persisted (test mock isolates writes from reads)
      const docId = createHash('sha256').update(issued.rawToken).digest('base64url');
      mocks.reads.set(`refresh_tokens/${docId}`, mocks.writes.get(`refresh_tokens/${docId}`));

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
      mocks.reads.set(`refresh_tokens/${docId}`, expired);
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
      mocks.reads.set(`refresh_tokens/${docId}`, expired);
      const record = await store.validate('past');
      assert.equal(record?.status, 'active');
      assert.ok(record!.expires_at < Date.now());
    });
  });
```

- [ ] **Step 2:** Run — expect failure (`validate` undefined).

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens
npm run test:build
node --test .tmp-test/test/auth/refresh-token-store.test.js
```

- [ ] **Step 3:** Add `validate` to `src/auth/refresh-token-store.ts`.

```typescript
  /**
   * Reads the record by raw token. Returns null if not found.
   * Does NOT enforce expiry or status — caller branches on those fields.
   */
  async validate(rawToken: string): Promise<RefreshTokenRecord | null> {
    const snap = await this.db.collection(COLLECTION).doc(hashToken(rawToken)).get();
    if (!snap.exists) return null;
    return snap.data() as RefreshTokenRecord;
  }
```

- [ ] **Step 4:** Run — expect green (4 new tests).

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/refresh-token-store.ts test/auth/refresh-token-store.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): RefreshTokenStore.validate()"
```

### Task 1.4: RefreshTokenStore.rotate() — TDD

**Files:**
- Modify: `test/auth/refresh-token-store.test.ts`
- Modify: `src/auth/refresh-token-store.ts`

- [ ] **Step 1:** Append tests for rotate. Note the transaction mock needs to be richer; redefine `makeMockFirestore` if needed to support `tx.get`/`tx.update`/`tx.set` with real semantics. Use this version (replace the body of `makeMockFirestore` in the test file):

```typescript
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
      where: mock.fn(() => ({
        get: mock.fn(async () => ({
          docs: Array.from(docs.entries())
            .filter(([p]) => p.startsWith(`${collection}/`))
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
```

Update the rest of the test file to use `mocks.docs` (not `mocks.writes`/`mocks.reads`). Earlier tests should still pass; replace the helper accordingly.

Then add the rotate tests:

```typescript
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

      // Old doc updated to status=rotated
      const oldNow = mocks.docs.get(`refresh_tokens/${oldDocId}`) as RefreshTokenRecord;
      assert.equal(oldNow.status, 'rotated');
      assert.ok(oldNow.rotated_at instanceof Date);

      // New doc written with status=active and same chain/TTL
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
```

- [ ] **Step 2:** Run — expect failure (`rotate` undefined).

- [ ] **Step 3:** Implement `rotate`:

```typescript
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
```

- [ ] **Step 4:** Run — expect green.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/refresh-token-store.ts test/auth/refresh-token-store.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): RefreshTokenStore.rotate() with atomic txn"
```

### Task 1.5: RefreshTokenStore.revokeChain() and revokeUser() — TDD

**Files:**
- Modify: `test/auth/refresh-token-store.test.ts`
- Modify: `src/auth/refresh-token-store.ts`

- [ ] **Step 1:** Append tests:

```typescript
  describe('revokeChain', () => {
    it('marks all docs sharing chainId as revoked', async () => {
      const a = await store.issue({ userId: 'u1', email: 'e1', scopes: ['drive'] });
      const b = await store.rotate(a.rawToken);
      const c = await store.rotate(b.rawToken);
      // Now: a and b are rotated, c is active. All share chainId.
      await store.revokeChain(a.chainId);
      for (const raw of [a.rawToken, b.rawToken, c.rawToken]) {
        const docId = createHash('sha256').update(raw).digest('base64url');
        const record = mocks.docs.get(`refresh_tokens/${docId}`) as RefreshTokenRecord;
        assert.equal(record.status, 'revoked', `expected ${raw.slice(0,6)}… revoked`);
      }
    });

    it('is a no-op when no docs match the chainId', async () => {
      await store.revokeChain('nonexistent-chain');
      // No throw, no writes
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
      // Other user untouched
      const otherDocId = createHash('sha256').update(otherUser.rawToken).digest('base64url');
      const otherRecord = mocks.docs.get(`refresh_tokens/${otherDocId}`) as RefreshTokenRecord;
      assert.equal(otherRecord.status, 'active');
    });
  });
```

- [ ] **Step 2:** Run — expect failure.

- [ ] **Step 3:** Implement:

```typescript
  /**
   * Revokes every doc sharing the given chain_id. Used on reuse detection
   * and explicit revocation by refresh-token.
   */
  async revokeChain(chainId: string): Promise<void> {
    const snap = await this.db
      .collection(COLLECTION)
      .where('chain_id', '==', chainId)
      .get();
    const writes = snap.docs.map((d) =>
      d.ref.update({ status: 'revoked' as RefreshTokenStatus }),
    );
    await Promise.all(writes);
  }

  /**
   * Revokes every chain belonging to a user. Used by revokeToken when the
   * presented token is an access JWT (not a refresh token).
   */
  async revokeUser(userId: string): Promise<void> {
    const snap = await this.db
      .collection(COLLECTION)
      .where('user_id', '==', userId)
      .get();
    const writes = snap.docs.map((d) =>
      d.ref.update({ status: 'revoked' as RefreshTokenStatus }),
    );
    await Promise.all(writes);
  }
```

- [ ] **Step 4:** Run — expect green.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/refresh-token-store.ts test/auth/refresh-token-store.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): RefreshTokenStore.revokeChain() + revokeUser()"
```

---

## Phase 2: Provider integration

### Task 2.1: Provider issues refresh_token in exchangeAuthorizationCode — TDD

**Files:**
- Modify: `test/integration/oauth-provider.test.ts` (extend existing test for `exchangeAuthorizationCode`)
- Modify: `src/auth/provider.ts`

- [ ] **Step 1:** Open `test/integration/oauth-provider.test.ts` and extend `createMockStore` (top of file) with refresh-token-store mock support. We will inject a separate mock alongside `FirestoreStore`.

Add this helper at the top of the file (after `createMockJwt`):

```typescript
function createMockRefreshTokenStore() {
  return {
    issue: mock.fn(async (_p: any) => ({
      rawToken: 'mock-refresh-token-raw',
      chainId: 'mock-chain-id',
      expiresAt: Date.now() + 90 * 24 * 60 * 60 * 1000,
    })),
    validate: mock.fn(async (_t: string) => null),
    rotate: mock.fn(async (_t: string) => ({
      rawToken: 'mock-rotated-token-raw',
      chainId: 'mock-chain-id',
      expiresAt: Date.now() + 90 * 24 * 60 * 60 * 1000,
    })),
    revokeChain: mock.fn(async (_c: string) => {}),
    revokeUser: mock.fn(async (_u: string) => {}),
  };
}
```

Update the constructor invocation in `beforeEach`:

```typescript
let refreshTokenStore: ReturnType<typeof createMockRefreshTokenStore>;

beforeEach(() => {
  store = createMockStore();
  googleOAuth = createMockGoogleOAuth();
  jwt = createMockJwt();
  refreshTokenStore = createMockRefreshTokenStore();
  provider = new DriveOAuthProvider(store, googleOAuth, jwt, PUBLIC_URL, TEST_SCOPES, refreshTokenStore as any);
});
```

Add a new `describe` block:

```typescript
describe('exchangeAuthorizationCode (with refresh token)', () => {
  beforeEach(() => {
    asMock(store.consumeAuthorizationCode).mock.mockImplementation(async () => ({
      claude_code_challenge: 'cc',
      user_id: 'google-user-123',
      email: 'user@relevantsearch.com',
      google_access_token: 'g-access',
      google_refresh_token: 'g-refresh',
      google_token_expires_at: Math.floor(Date.now() / 1000) + 3600,
      created_at: new Date(),
    }));
  });

  it('returns both access_token and refresh_token', async () => {
    const tokens = await provider.exchangeAuthorizationCode(MOCK_CLIENT, 'some-auth-code');
    assert.equal(tokens.access_token, 'mock-jwt-token');
    assert.equal(tokens.refresh_token, 'mock-refresh-token-raw');
    assert.equal(tokens.expires_in, 3600);
  });

  it('issues refresh token with the user identity from the auth-code record', async () => {
    await provider.exchangeAuthorizationCode(MOCK_CLIENT, 'some-auth-code');
    const issueCalls = asMock(refreshTokenStore.issue).mock.calls;
    assert.equal(issueCalls.length, 1);
    const issuedWith = issueCalls[0].arguments[0];
    assert.equal(issuedWith.userId, 'google-user-123');
    assert.equal(issuedWith.email, 'user@relevantsearch.com');
    assert.deepEqual(issuedWith.scopes, TEST_SCOPES);
  });
});
```

- [ ] **Step 2:** Run — expect failures (provider constructor mismatch + missing refresh_token in response).

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens
npm run test:build
node --test .tmp-test/test/integration/oauth-provider.test.js
```

- [ ] **Step 3:** Modify `src/auth/provider.ts`:

a. Add import at the top:

```typescript
import type { RefreshTokenStore } from './refresh-token-store.js';
```

b. Update the constructor:

```typescript
  constructor(
    private readonly store: FirestoreStore,
    private readonly googleOAuth: GoogleOAuth,
    private readonly jwt: McpJwt,
    private readonly publicUrl: string,
    private readonly scopes: string[],
    private readonly refreshTokenStore: RefreshTokenStore,
  ) {
    // ... existing body unchanged
```

c. Update `exchangeAuthorizationCode` to issue a refresh token. Replace the `return` block at the end:

```typescript
    const refresh = await this.refreshTokenStore.issue({
      userId: record.user_id,
      email: record.email,
      scopes: this.scopes,
    });

    return {
      access_token: accessToken,
      refresh_token: refresh.rawToken,
      token_type: 'bearer',
      expires_in: 3600,
      scope: this.scopes.join(' '),
    };
```

- [ ] **Step 4:** Run — expect the new tests green AND the existing oauth-provider tests still green.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/provider.ts test/integration/oauth-provider.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): issue refresh_token alongside access JWT"
```

### Task 2.2: Provider exchangeRefreshToken — TDD (happy path + invalid_grant)

**Files:**
- Create: `test/integration/refresh-flow.test.ts`
- Modify: `src/auth/provider.ts`

- [ ] **Step 1:** Create the integration test file `test/integration/refresh-flow.test.ts`:

```typescript
import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { DriveOAuthProvider } from '../../src/auth/provider.js';
import type { FirestoreStore } from '../../src/auth/firestore-store.js';
import type { GoogleOAuth } from '../../src/auth/google-oauth.js';
import type { McpJwt } from '../../src/auth/jwt.js';
import type { RefreshTokenRecord } from '../../src/auth/types.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

const TEST_SCOPES = ['openid', 'email', 'https://www.googleapis.com/auth/drive'];
const PUBLIC_URL = 'https://drive-mcp.example.com';
const MOCK_CLIENT: OAuthClientInformationFull = {
  client_id: 'cid', client_secret: 'cs', redirect_uris: ['https://claude.ai/cb'],
} as OAuthClientInformationFull;

function activeRecord(overrides: Partial<RefreshTokenRecord> = {}): RefreshTokenRecord {
  return {
    user_id: 'u1',
    email: 'u1@relevantsearch.com',
    scopes: TEST_SCOPES,
    chain_id: 'chain-1',
    created_at: new Date(),
    expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000,
    status: 'active',
    rotated_at: null,
    ...overrides,
  };
}

function makeMocks() {
  const store = {
    getOAuthClient: mock.fn(async () => undefined),
    saveOAuthClient: mock.fn(async () => {}),
    getUserTokens: mock.fn(async () => undefined),
    saveUserTokens: mock.fn(async () => {}),
    getPendingAuthorization: mock.fn(async () => undefined),
    savePendingAuthorization: mock.fn(async () => {}),
    deletePendingAuthorization: mock.fn(async () => {}),
    getAuthorizationCode: mock.fn(async () => undefined),
    saveAuthorizationCode: mock.fn(async () => {}),
    consumeAuthorizationCode: mock.fn(async () => undefined),
  } as unknown as FirestoreStore;

  const googleOAuth = {
    authorizationUrl: mock.fn(() => 'https://accounts.google.com/?mock=1'),
    exchangeCode: mock.fn(async () => ({})),
    refreshAccessToken: mock.fn(async () => ({})),
  } as unknown as GoogleOAuth;

  const jwt = {
    sign: mock.fn(async () => 'jwt-' + Math.random().toString(36).slice(2, 8)),
    verify: mock.fn(async () => ({ sub: 'u1', email: 'u1@relevantsearch.com', scope: TEST_SCOPES.join(' '), exp: 0 })),
  } as unknown as McpJwt;

  const refreshTokenStore = {
    issue: mock.fn(async () => ({ rawToken: 'r-init', chainId: 'chain-1', expiresAt: Date.now() + 90 * 24 * 60 * 60 * 1000 })),
    validate: mock.fn(async () => null as RefreshTokenRecord | null),
    rotate: mock.fn(async () => ({ rawToken: 'r-new', chainId: 'chain-1', expiresAt: Date.now() + 60 * 24 * 60 * 60 * 1000 })),
    revokeChain: mock.fn(async () => {}),
    revokeUser: mock.fn(async () => {}),
  };

  return { store, googleOAuth, jwt, refreshTokenStore };
}

describe('exchangeRefreshToken', () => {
  let mocks: ReturnType<typeof makeMocks>;
  let provider: DriveOAuthProvider;

  beforeEach(() => {
    mocks = makeMocks();
    provider = new DriveOAuthProvider(
      mocks.store, mocks.googleOAuth, mocks.jwt,
      PUBLIC_URL, TEST_SCOPES, mocks.refreshTokenStore as any,
    );
  });

  it('happy path: validates, rotates, mints JWT, returns new pair', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => activeRecord());

    const tokens = await provider.exchangeRefreshToken(MOCK_CLIENT, 'r-init');
    assert.match(tokens.access_token, /^jwt-/);
    assert.equal(tokens.refresh_token, 'r-new');
    assert.equal(tokens.expires_in, 3600);
    assert.equal((mocks.refreshTokenStore.rotate as any).mock.calls.length, 1);
    assert.equal((mocks.refreshTokenStore.revokeChain as any).mock.calls.length, 0);
  });

  it('returns invalid_grant when refresh_token is unknown', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => null);
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'unknown'),
      /invalid_grant/,
    );
  });

  it('returns invalid_grant when refresh_token is revoked', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => activeRecord({ status: 'revoked' }));
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'revoked'),
      /invalid_grant/,
    );
  });

  it('returns invalid_grant when refresh_token is expired', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () =>
      activeRecord({ expires_at: Date.now() - 1000 }));
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'old'),
      /invalid_grant/,
    );
  });
});
```

- [ ] **Step 2:** Run — expect failures (`exchangeRefreshToken` still throws "Refresh tokens not supported").

```bash
npm run test:build
node --test .tmp-test/test/integration/refresh-flow.test.js
```

- [ ] **Step 3:** Replace `exchangeRefreshToken` in `src/auth/provider.ts`. Add a custom error class at the top of the file (or import `InvalidGrantError` from `google-oauth.ts` — it's already exported and reusable):

```typescript
import { GoogleOAuth, InvalidGrantError } from './google-oauth.js';
```

Replace the method body:

```typescript
  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    _resource?: URL,
  ): Promise<OAuthTokens> {
    const record = await this.refreshTokenStore.validate(refreshToken);
    if (!record) {
      throw new InvalidGrantError('invalid_grant');
    }
    if (record.status === 'revoked') {
      throw new InvalidGrantError('invalid_grant');
    }
    if (record.expires_at < Date.now()) {
      throw new InvalidGrantError('invalid_grant');
    }
    if (record.status === 'rotated') {
      // Reuse detected (grace window handled in Task 2.3)
      await this.refreshTokenStore.revokeChain(record.chain_id);
      throw new InvalidGrantError('invalid_grant');
    }

    const newRefresh = await this.refreshTokenStore.rotate(refreshToken);
    const accessToken = await this.jwt.sign({
      sub: record.user_id,
      email: record.email,
      scope: record.scopes.join(' '),
    });

    return {
      access_token: accessToken,
      refresh_token: newRefresh.rawToken,
      token_type: 'bearer',
      expires_in: 3600,
      scope: record.scopes.join(' '),
    };
  }
```

- [ ] **Step 4:** Run — expect 4 tests green.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/provider.ts test/integration/refresh-flow.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): exchangeRefreshToken happy path + invalid_grant"
```

### Task 2.3: Reuse detection beyond grace + 5s grace window — TDD

**Files:**
- Modify: `test/integration/refresh-flow.test.ts`
- Modify: `src/auth/provider.ts`

- [ ] **Step 1:** Append tests:

```typescript
  it('reuse detection: rotated token presented beyond grace revokes chain', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () =>
      activeRecord({ status: 'rotated', rotated_at: new Date(Date.now() - 10_000) }));
    await assert.rejects(
      () => provider.exchangeRefreshToken(MOCK_CLIENT, 'leaked'),
      /invalid_grant/,
    );
    assert.equal((mocks.refreshTokenStore.revokeChain as any).mock.calls.length, 1);
  });

  it('grace window: same raw token within 5s returns identical pair, no chain revoke', async () => {
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () => activeRecord());
    const first = await provider.exchangeRefreshToken(MOCK_CLIENT, 'r-init');

    // Simulate that after rotation, the next validate sees the now-rotated record
    (mocks.refreshTokenStore.validate as any).mock.mockImplementation(async () =>
      activeRecord({ status: 'rotated', rotated_at: new Date() }));

    const second = await provider.exchangeRefreshToken(MOCK_CLIENT, 'r-init');
    assert.equal(second.access_token, first.access_token);
    assert.equal(second.refresh_token, first.refresh_token);
    assert.equal((mocks.refreshTokenStore.revokeChain as any).mock.calls.length, 0);
    // Rotate called exactly once (only first call rotates)
    assert.equal((mocks.refreshTokenStore.rotate as any).mock.calls.length, 1);
  });
```

- [ ] **Step 2:** Run — expect the grace test to fail (currently the second call detects rotated → revokes chain).

- [ ] **Step 3:** Add a grace cache to provider. Add a private field and helper:

```typescript
import { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
// ... existing imports

const GRACE_WINDOW_MS = 5_000;

interface GraceEntry {
  tokens: OAuthTokens;
  expiresAt: number;
}

export class DriveOAuthProvider implements OAuthServerProvider {
  // ... existing fields
  private readonly graceCache = new Map<string, GraceEntry>();
```

Update `exchangeRefreshToken`. Insert grace-cache check at the top, and a write after rotation:

```typescript
  async exchangeRefreshToken(
    _client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    _resource?: URL,
  ): Promise<OAuthTokens> {
    // Idempotent retry within grace window
    const cached = this.graceCache.get(refreshToken);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.tokens;
    }
    // Lazy expiry of stale grace entries
    if (cached) this.graceCache.delete(refreshToken);

    const record = await this.refreshTokenStore.validate(refreshToken);
    if (!record) throw new InvalidGrantError('invalid_grant');
    if (record.status === 'revoked') throw new InvalidGrantError('invalid_grant');
    if (record.expires_at < Date.now()) throw new InvalidGrantError('invalid_grant');
    if (record.status === 'rotated') {
      // True reuse (grace window already missed). Revoke chain.
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
```

- [ ] **Step 4:** Run — both new tests green, prior tests still green.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/provider.ts test/integration/refresh-flow.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): reuse detection + 5s grace window for retries"
```

### Task 2.4: revokeToken implementation — TDD

**Files:**
- Modify: `test/integration/oauth-provider.test.ts`
- Modify: `src/auth/provider.ts`

- [ ] **Step 1:** Append tests in `oauth-provider.test.ts`:

```typescript
describe('revokeToken', () => {
  beforeEach(() => {
    refreshTokenStore = createMockRefreshTokenStore();
    provider = new DriveOAuthProvider(store, googleOAuth, jwt, PUBLIC_URL, TEST_SCOPES, refreshTokenStore as any);
  });

  it('revokes the chain when given a valid refresh token', async () => {
    asMock(refreshTokenStore.validate).mock.mockImplementation(async () => ({
      user_id: 'u1', email: 'e1', scopes: TEST_SCOPES,
      chain_id: 'chain-x', created_at: new Date(),
      expires_at: Date.now() + 1000, status: 'active', rotated_at: null,
    }));
    await provider.revokeToken!(MOCK_CLIENT, { token: 'r-1' });
    const chainCalls = asMock(refreshTokenStore.revokeChain).mock.calls;
    assert.equal(chainCalls.length, 1);
    assert.equal(chainCalls[0].arguments[0], 'chain-x');
  });

  it('revokes by user when given a valid access token (JWT)', async () => {
    asMock(refreshTokenStore.validate).mock.mockImplementation(async () => null);
    asMock(jwt.verify).mock.mockImplementation(async () => ({
      sub: 'user-jwt', email: 'e@x', scope: TEST_SCOPES.join(' '),
      exp: Math.floor(Date.now() / 1000) + 3600,
    }));
    await provider.revokeToken!(MOCK_CLIENT, { token: 'jwt-token' });
    const userCalls = asMock(refreshTokenStore.revokeUser).mock.calls;
    assert.equal(userCalls.length, 1);
    assert.equal(userCalls[0].arguments[0], 'user-jwt');
  });

  it('returns silently when token is unknown (RFC 7009)', async () => {
    asMock(refreshTokenStore.validate).mock.mockImplementation(async () => null);
    asMock(jwt.verify).mock.mockImplementation(async () => { throw new Error('invalid'); });
    // Must not throw — RFC 7009 mandates 200 even for unknown tokens
    await provider.revokeToken!(MOCK_CLIENT, { token: 'garbage' });
  });
});
```

- [ ] **Step 2:** Run — expect failure (`revokeToken` not implemented).

- [ ] **Step 3:** Replace the `// revokeToken is optional — not implemented for v1` comment in `provider.ts` with:

```typescript
  /**
   * RFC 7009 token revocation. Accepts both refresh and access tokens.
   * Returns silently for unknown tokens (no information leak).
   */
  async revokeToken(
    _client: OAuthClientInformationFull,
    request: { token: string; token_type_hint?: string },
  ): Promise<void> {
    // Try refresh-token path first (cheaper than JWT verify on misses)
    const record = await this.refreshTokenStore.validate(request.token);
    if (record) {
      await this.refreshTokenStore.revokeChain(record.chain_id);
      return;
    }
    // Fall back to access-token path
    try {
      const payload = await this.jwt.verify(request.token);
      await this.refreshTokenStore.revokeUser(payload.sub);
    } catch {
      // Unknown token — RFC 7009 says return 200 silently
    }
  }
```

- [ ] **Step 4:** Run — 3 new tests green.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/auth/provider.ts test/integration/oauth-provider.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(auth): revokeToken impl per RFC 7009"
```

---

## Phase 3: Wiring & full test sweep

### Task 3.1: Wire RefreshTokenStore in src/index.ts

**Files:**
- Modify: `src/index.ts` around line 925-932

- [ ] **Step 1:** Read the current construction site.

```bash
sed -n '920,935p' ~/git/RS/google-drive-mcp-team_feat-refresh-tokens/src/index.ts
```

- [ ] **Step 2:** Add the import at the top of `src/index.ts`:

```typescript
import { RefreshTokenStore } from './auth/refresh-token-store.js';
```

- [ ] **Step 3:** In the provider construction block (was lines 925-932), add the new store and pass it. Replace:

```typescript
  const store = new FirestoreStore();
  const googleOAuth = new GoogleOAuth({ ... });
  const jwt = new McpJwt(signingKey);
  const provider = new DriveOAuthProvider(store, googleOAuth, jwt, publicUrl, scopes);
```

With:

```typescript
  const store = new FirestoreStore();
  const googleOAuth = new GoogleOAuth({ ... });
  const jwt = new McpJwt(signingKey);
  // FirestoreStore exposes its `db` via a getter — but the existing code does
  // not. Construct a Firestore directly here (same ADC, same project).
  const refreshTokenStore = new RefreshTokenStore(new (await import('@google-cloud/firestore')).Firestore());
  const provider = new DriveOAuthProvider(store, googleOAuth, jwt, publicUrl, scopes, refreshTokenStore);
```

If `src/index.ts` is not in an async context at this point, instead use a top-level import:

```typescript
import { Firestore } from '@google-cloud/firestore';
// ...
const refreshTokenStore = new RefreshTokenStore(new Firestore());
```

- [ ] **Step 4:** Build to verify wiring.

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens
npm run build
```

Expected: build succeeds.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add src/index.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "feat(server): wire RefreshTokenStore into provider construction"
```

### Task 3.2: Extend e2e-oauth-flow with refresh round-trip

**Files:**
- Modify: `test/integration/e2e-oauth-flow.test.ts`

- [ ] **Step 1:** At the end of the existing happy-path e2e test (after the `/mcp` call succeeds with the bearer JWT), add a refresh round-trip step. Find the test that ends with the bearer call and append:

```typescript
    // 7. Refresh round-trip — POST /token with grant_type=refresh_token
    const refreshTokenFromInitial = tokens.refresh_token;
    assert.ok(refreshTokenFromInitial, 'initial /token response must include refresh_token');

    const refreshRes = await fetch(`${baseUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshTokenFromInitial,
        client_id: clientId,
        client_secret: clientSecret,
      }).toString(),
    });
    assert.equal(refreshRes.status, 200);
    const refreshed = await refreshRes.json() as any;
    assert.ok(refreshed.access_token);
    assert.ok(refreshed.refresh_token);
    assert.notEqual(refreshed.access_token, tokens.access_token);
    assert.notEqual(refreshed.refresh_token, refreshTokenFromInitial);

    // 8. New JWT works against /mcp
    const mcpRes2 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${refreshed.access_token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize', params: {} }),
    });
    assert.equal(mcpRes2.status, 200);
```

- [ ] **Step 2:** The e2e test uses `makeStoreStub()` for FirestoreStore. The provider constructor now also requires a `RefreshTokenStore`. Add a Map-based stub at the top of the test file:

```typescript
function makeRefreshTokenStoreStub() {
  const docs = new Map<string, any>();
  let counter = 0;
  return {
    issue: async (params: { userId: string; email: string; scopes: string[] }) => {
      const raw = `r-${++counter}`;
      docs.set(raw, { ...params, chainId: `chain-${counter}`, status: 'active', rotated_at: null,
                      expires_at: Date.now() + 90 * 24 * 60 * 60 * 1000, created_at: new Date() });
      return { rawToken: raw, chainId: `chain-${counter}`, expiresAt: Date.now() + 90 * 24 * 60 * 60 * 1000 };
    },
    validate: async (raw: string) => {
      const d = docs.get(raw);
      return d ? { ...d, user_id: d.userId, email: d.email, scopes: d.scopes, chain_id: d.chainId } : null;
    },
    rotate: async (raw: string) => {
      const old = docs.get(raw);
      if (!old) throw new Error('Refresh token not found');
      docs.set(raw, { ...old, status: 'rotated', rotated_at: new Date() });
      const newRaw = `r-${++counter}`;
      docs.set(newRaw, { ...old, status: 'active', rotated_at: null, created_at: new Date() });
      return { rawToken: newRaw, chainId: old.chainId, expiresAt: old.expires_at };
    },
    revokeChain: async (chainId: string) => {
      for (const [k, v] of docs) if (v.chainId === chainId) docs.set(k, { ...v, status: 'revoked' });
    },
    revokeUser: async (userId: string) => {
      for (const [k, v] of docs) if (v.userId === userId) docs.set(k, { ...v, status: 'revoked' });
    },
  };
}
```

Wire it where the provider is constructed inside the test setup. Find `new DriveOAuthProvider(...)` in `e2e-oauth-flow.test.ts` and pass `makeRefreshTokenStoreStub() as any` as the 6th argument.

- [ ] **Step 3:** Run the e2e test.

```bash
cd ~/git/RS/google-drive-mcp-team_feat-refresh-tokens
npm run test:build
node --test .tmp-test/test/integration/e2e-oauth-flow.test.js
```

Expected: existing test plus new refresh steps green.

- [ ] **Step 4:** Run the full suite.

```bash
npm test 2>&1 | tee /tmp/full-suite.log
```

Compare against `BASELINE.md` from Task 0.2: every test that passed on master must still pass. Pre-existing failures may persist (acknowledged). Net new passing tests should equal the count of new tests added in Phases 1-3.

- [ ] **Step 5:** Commit.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add test/integration/e2e-oauth-flow.test.ts
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "test(e2e): refresh round-trip in oauth flow"
```

---

## Phase 4: PR

### Task 4.1: Mirror design doc to fork

**Files:**
- Create in fork: `docs/projects/2026-05-02-drive-mcp-refresh-tokens/index.md`
- Create in fork: `docs/projects/2026-05-02-drive-mcp-refresh-tokens/2026-05-02-drive-mcp-refresh-tokens-design.md`
- Create in fork: `docs/projects/2026-05-02-drive-mcp-refresh-tokens/2026-05-02-drive-mcp-refresh-tokens-plan.md`

- [ ] **Step 1:** Copy the docs from rs_infra into the fork worktree (matches the 2026-04-15 mirror pattern).

```bash
mkdir -p ~/git/RS/google-drive-mcp-team_feat-refresh-tokens/docs/projects/2026-05-02-drive-mcp-refresh-tokens
cp ~/git/RS/main/rs_infra_feat-drive-mcp-refresh-tokens/docs/projects/2026-05-02-drive-mcp-refresh-tokens/* \
   ~/git/RS/google-drive-mcp-team_feat-refresh-tokens/docs/projects/2026-05-02-drive-mcp-refresh-tokens/
```

- [ ] **Step 2:** Update relative links inside the mirrored files. The mirror uses no relative links to the predecessor since `2026-04-15-drive-mcp-team` is in rs_infra, not the fork. Edit `index.md` in the fork to remove or rewrite the predecessor link.

- [ ] **Step 3:** Commit the mirror.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens add docs/projects/2026-05-02-drive-mcp-refresh-tokens/
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens commit -m "docs(drive-mcp): mirror refresh-token design + plan from rs_infra"
```

### Task 4.2: Push branch and create PR

**Files:** none

- [ ] **Step 1:** Push the branch.

```bash
git -C ~/git/RS/google-drive-mcp-team_feat-refresh-tokens push -u origin feat/refresh-tokens
```

- [ ] **Step 2:** Create the PR.

```bash
gh pr create --repo RelevantSearch/google-drive-mcp \
  --base master \
  --head feat/refresh-tokens \
  --title "feat(auth): OAuth 2.1 refresh-token support in AS hop" \
  --body "$(cat <<'EOF'
## Summary
- Implement `RefreshTokenStore` (Firestore-backed, opaque random tokens, hashed at rest)
- Wire issuance into `exchangeAuthorizationCode`; replace stub `exchangeRefreshToken` with validate → rotate → mint flow
- Rotate-on-use semantics with reuse detection (chain-revoke) and 5-second idempotent-retry grace window
- Implement `revokeToken` per RFC 7009
- 90-day chain TTL (forced re-auth checkpoint, copied across rotations)
- AS hop never calls Google during refresh; lazy Google refresh continues on the tool-call path via existing `user-token.ts`

Eliminates the 2-3 day forced relogin cycle on `drive-mcp.relevantsearch.com`.

Design + plan: `docs/projects/2026-05-02-drive-mcp-refresh-tokens/`.

## Test plan
- [x] Unit: `test/auth/refresh-token-store.test.ts` (issue, validate, rotate, revokeChain, revokeUser)
- [x] Integration: `test/integration/refresh-flow.test.ts` (happy path, invalid_grant variants, reuse detection, grace window)
- [x] Integration: revokeToken in `test/integration/oauth-provider.test.ts`
- [x] E2E: refresh round-trip in `test/integration/e2e-oauth-flow.test.ts`
- [x] `npm test` clean against pre-existing baseline
- [ ] Post-merge smoke (Stefan): reconnect in claude.ai, make Drive call, wait 1h, make another Drive call without prompt
EOF
)"
```

- [ ] **Step 3:** Capture the PR URL in the next response so monitoring can attach.

### Task 4.3: Monitor CI and address review comments

**Files:** none

- [ ] **Step 1:** Watch CI.

```bash
gh pr checks <pr_number> --watch --repo RelevantSearch/google-drive-mcp
```

- [ ] **Step 2:** If CI fails, diagnose locally first per `feedback_iterate_locally_not_ci`. Push fixes.

- [ ] **Step 3:** When review comments arrive, reply inline per `feedback_reply_inline_pr_comments`. Never resolve, never merge, never close.

```bash
gh pr view <pr_number> --comments --repo RelevantSearch/google-drive-mcp
```

- [ ] **Step 4:** After Stefan merges, run post-merge smoke per `### Task 4.4`.

### Task 4.4: Post-merge smoke

**Files:** none

- [ ] **Step 1:** Verify CI deploy succeeded.

```bash
gh run list --branch master --limit 3 --repo RelevantSearch/google-drive-mcp
gh run view <run_id> --repo RelevantSearch/google-drive-mcp
```

- [ ] **Step 2:** Confirm Cloud Run revision rolled.

```bash
gcloud run services describe drive-mcp \
  --project=rs-workspace-integrations \
  --region=us-central1 \
  --format='value(status.latestReadyRevisionName)'
```

Expected: a new revision (`drive-mcp-00005-xxx` or higher) different from the pre-deploy revision.

- [ ] **Step 3:** Stefan reconnects the connector at claude.ai (Settings > Connectors > Relevant Drive > Connect). Run a Drive call (e.g. "List my 5 most recent Google Docs").

- [ ] **Step 4:** Wait at least 1 hour. Run another Drive call. Confirm no reconnect prompt — proves AS-hop refresh works.

- [ ] **Step 5:** Inspect Firestore.

```bash
gcloud firestore documents list refresh_tokens \
  --project=rs-workspace-integrations \
  --limit=10 \
  --format='value(name,fields.status.stringValue,fields.chain_id.stringValue)'
```

Expected: at least two docs sharing a `chain_id` — one `rotated`, one `active`.

- [ ] **Step 6:** Update the rs_infra `index.md` Status field from `Draft` to `Complete` and append a v2 changelog.

```bash
# In the rs_infra worktree
cd ~/git/RS/main/rs_infra_feat-drive-mcp-refresh-tokens
# edit docs/projects/2026-05-02-drive-mcp-refresh-tokens/index.md:
#   - Status: Complete
#   - Add ## Changelog section with ### v2 entry
git add docs/projects/2026-05-02-drive-mcp-refresh-tokens/index.md
git commit -m "docs(drive-mcp): mark refresh-token project complete"
```

(rs_infra PR for these doc updates is separate and small; can be opened together with the next rs_infra PR rather than standalone.)

---

## Self-review notes (writing-plans skill)

**Spec coverage check:**

| Spec section | Plan coverage |
|---|---|
| RefreshTokenStore (issue/validate/rotate/revoke) | Tasks 1.1-1.5 |
| 90-day chain TTL inherited on rotation | Task 1.4 (`oldRecord.expires_at` copied verbatim) |
| Hashing at rest | Task 1.2 (SHA-256 base64url docId) |
| Atomic rotation | Task 1.4 (`db.runTransaction`) |
| Reuse detection → chain revoke | Task 2.3 |
| 5-second idempotent grace window | Task 2.3 (in-memory `graceCache`) |
| `exchangeAuthorizationCode` issues refresh_token | Task 2.1 |
| `exchangeRefreshToken` validate→rotate→mint | Task 2.2 |
| `revokeToken` (RFC 7009) | Task 2.4 |
| AS hop does NOT call Google during refresh | Task 2.2 (no `googleOAuth.refreshAccessToken` in handler) |
| Wiring in `src/index.ts` | Task 3.1 |
| Tests: unit, integration, e2e | Tasks 1.x, 2.2-2.4, 3.2 |
| Mirror design+plan to fork | Task 4.1 |
| Deploy via existing CI | Task 4.2 push triggers `deploy.yml` |
| Post-deploy smoke | Task 4.4 |

**Type consistency:**
- `RefreshTokenRecord` field names are snake_case throughout (matching `UserTokens` precedent in the codebase).
- `IssueResult` and `rotate()` return type use camelCase (`rawToken`, `chainId`, `expiresAt`) since they cross the JS/method boundary.
- `RefreshTokenStore.validate()` returns `RefreshTokenRecord | null`, never throws on absence (matches `getOAuthClient` pattern).

**Placeholder scan:** none.

## Changelog

### v1 - 2026-05-02

Initial plan.
