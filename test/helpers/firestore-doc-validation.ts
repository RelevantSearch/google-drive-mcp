/**
 * Replicates the real @google-cloud/firestore client's document validation:
 * any undefined value (top-level or nested) is rejected client-side, before
 * the write reaches the wire:
 *
 *   Value for argument "data" is not a valid Firestore document. Cannot use
 *   "undefined" as a Firestore value (found in field "<path>").
 *
 * Every FirestoreStore test double's save method must run its document
 * through this validator — a stub more permissive than the real client
 * lets the suite green-light writes production rejects (the public-client
 * registration 500 shipped exactly that way).
 */
export function assertValidFirestoreDocument(data: unknown, path = ''): void {
  if (data === undefined) {
    throw new Error(
      `Value for argument "data" is not a valid Firestore document. ` +
      `Cannot use "undefined" as a Firestore value (found in field "${path}").`,
    );
  }
  if (data === null || typeof data !== 'object' || data instanceof Date) return;
  for (const [key, value] of Object.entries(data)) {
    assertValidFirestoreDocument(value, path ? `${path}.${key}` : key);
  }
}
