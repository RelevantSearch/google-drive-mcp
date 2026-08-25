/**
 * Mirror real Firestore's write validation: any `undefined` value, top-level
 * or nested, is rejected. The deployed FirestoreStore runs on a bare
 * `new Firestore()` (no ignoreUndefinedProperties), so every in-memory stub
 * standing in for it must enforce the same constraint on EVERY write method —
 * a stub looser than the real store hides production 500s (the /register
 * public-client crash was exactly this class).
 */
export function assertFirestoreWritable(doc: unknown, path = ''): void {
  if (doc === undefined) {
    throw new Error(
      `Cannot use "undefined" as a Firestore value${path ? ` (found in field "${path}")` : ''}`,
    );
  }
  if (doc === null || typeof doc !== 'object' || doc instanceof Date) return;
  for (const [key, value] of Object.entries(doc as Record<string, unknown>)) {
    assertFirestoreWritable(value, path ? `${path}.${key}` : key);
  }
}
