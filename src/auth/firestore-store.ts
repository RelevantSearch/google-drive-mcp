/**
 * Firestore CRUD for auth collections.
 *
 * Collections:
 *   oauth_clients           — dynamic client registrations
 *   user_tokens             — Google tokens per user
 *   pending_authorizations  — in-flight OAuth flows (keyed by Google state)
 *   authorization_codes     — issued codes awaiting exchange (keyed by code)
 *
 * IMPORTANT: consumeAuthorizationCode uses db.runTransaction() for atomic
 * get+delete to prevent double-mint on concurrent /token requests.
 */

import { Firestore } from '@google-cloud/firestore';
import type {
  OAuthClient,
  UserTokens,
  PendingAuthorization,
  AuthCodeRecord,
} from './types.js';

export class FirestoreStore {
  private db: Firestore;

  constructor(db?: Firestore) {
    // No args — ADC handles project on Cloud Run
    this.db = db ?? new Firestore();
  }

  // ── oauth_clients ──────────────────────────────────────────────

  async getOAuthClient(clientId: string): Promise<OAuthClient | undefined> {
    const snap = await this.db.collection('oauth_clients').doc(clientId).get();
    if (!snap.exists) return undefined;
    return snap.data() as OAuthClient;
  }

  async saveOAuthClient(client: OAuthClient): Promise<void> {
    await this.db
      .collection('oauth_clients')
      .doc(client.client_id)
      .set(client);
  }

  // ── user_tokens ────────────────────────────────────────────────

  async getUserTokens(userId: string): Promise<UserTokens | undefined> {
    const snap = await this.db.collection('user_tokens').doc(userId).get();
    if (!snap.exists) return undefined;
    return snap.data() as UserTokens;
  }

  async saveUserTokens(tokens: UserTokens): Promise<void> {
    await this.db
      .collection('user_tokens')
      .doc(tokens.user_id)
      .set(tokens);
  }

  // ── pending_authorizations ─────────────────────────────────────

  async getPendingAuthorization(
    googleState: string,
  ): Promise<PendingAuthorization | undefined> {
    const snap = await this.db
      .collection('pending_authorizations')
      .doc(googleState)
      .get();
    if (!snap.exists) return undefined;
    return snap.data() as PendingAuthorization;
  }

  async savePendingAuthorization(
    googleState: string,
    pending: PendingAuthorization,
  ): Promise<void> {
    await this.db
      .collection('pending_authorizations')
      .doc(googleState)
      .set(pending);
  }

  async deletePendingAuthorization(googleState: string): Promise<void> {
    await this.db
      .collection('pending_authorizations')
      .doc(googleState)
      .delete();
  }

  // ── authorization_codes ────────────────────────────────────────

  /**
   * Non-consuming read. Used by challengeForAuthorizationCode to return
   * the stored PKCE challenge without deleting the code record.
   */
  async getAuthorizationCode(
    code: string,
  ): Promise<AuthCodeRecord | undefined> {
    const snap = await this.db
      .collection('authorization_codes')
      .doc(code)
      .get();
    if (!snap.exists) return undefined;
    return snap.data() as AuthCodeRecord;
  }

  async saveAuthorizationCode(
    code: string,
    record: AuthCodeRecord,
  ): Promise<void> {
    await this.db.collection('authorization_codes').doc(code).set(record);
  }

  /**
   * Atomic get + delete inside a Firestore transaction.
   * Prevents double-mint if concurrent /token requests arrive with the same code.
   * Returns undefined if the code doesn't exist (already consumed or never issued).
   */
  async consumeAuthorizationCode(
    code: string,
  ): Promise<AuthCodeRecord | undefined> {
    const docRef = this.db.collection('authorization_codes').doc(code);

    return this.db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) return undefined;
      tx.delete(docRef);
      return snap.data() as AuthCodeRecord;
    });
  }
}
