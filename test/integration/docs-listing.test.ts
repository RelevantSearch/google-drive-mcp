import assert from 'node:assert/strict';
import { describe, it, before, after, beforeEach } from 'node:test';
import { setupTestServer, callTool, type TestContext } from '../helpers/setup-server.js';

describe('Docs listing tools', () => {
  let ctx: TestContext;

  before(async () => { ctx = await setupTestServer(); });
  after(async () => { await ctx.cleanup(); });
  beforeEach(() => {
    ctx.mocks.drive.tracker.reset();
  });

  // --- listGoogleDocs ---
  describe('listGoogleDocs', () => {
    it('happy path', async () => {
      ctx.mocks.drive.service.files.list._setImpl(async () => ({
        data: {
          files: [{
            id: 'doc-1', name: 'My Document', modifiedTime: '2025-01-01',
            webViewLink: 'https://docs.google.com/doc-1',
            owners: [{ displayName: 'Owner', emailAddress: 'owner@test.com' }],
          }],
        },
      }));
      const res = await callTool(ctx.client, 'listGoogleDocs', {});
      assert.equal(res.isError, false);
      assert.ok(res.content[0].text.includes('My Document'));
    });

    it('no results', async () => {
      ctx.mocks.drive.service.files.list._setImpl(async () => ({ data: { files: [] } }));
      const res = await callTool(ctx.client, 'listGoogleDocs', {});
      assert.equal(res.isError, false);
      assert.ok(res.content[0].text.includes('No Google Docs'));
    });

    it('defaults orderBy to modifiedTime desc', async () => {
      await callTool(ctx.client, 'listGoogleDocs', {});
      const calls = ctx.mocks.drive.tracker.getCalls('files.list');
      assert.equal(calls.length, 1);
      assert.equal(calls[0].args[0].orderBy, 'modifiedTime desc');
    });

    it('passes orderBy through verbatim', async () => {
      await callTool(ctx.client, 'listGoogleDocs', { orderBy: 'createdTime desc' });
      const calls = ctx.mocks.drive.tracker.getCalls('files.list');
      assert.equal(calls[0].args[0].orderBy, 'createdTime desc');
    });

    it('appends "and \'me\' in owners" when ownedByMe is true', async () => {
      await callTool(ctx.client, 'listGoogleDocs', { ownedByMe: true });
      const calls = ctx.mocks.drive.tracker.getCalls('files.list');
      assert.match(calls[0].args[0].q, /'me' in owners/);
    });

    it('omits owner clause when ownedByMe is unset', async () => {
      await callTool(ctx.client, 'listGoogleDocs', {});
      const calls = ctx.mocks.drive.tracker.getCalls('files.list');
      assert.doesNotMatch(calls[0].args[0].q, /'me' in owners/);
    });
  });

  // --- getDocumentInfo ---
  describe('getDocumentInfo', () => {
    it('happy path', async () => {
      ctx.mocks.drive.service.files.get._setImpl(async () => ({
        data: {
          id: 'doc-1', name: 'My Document', mimeType: 'application/vnd.google-apps.document',
          createdTime: '2025-01-01', modifiedTime: '2025-01-02',
          webViewLink: 'https://docs.google.com/doc-1', shared: true,
          owners: [{ displayName: 'Owner', emailAddress: 'owner@test.com' }],
        },
      }));
      const res = await callTool(ctx.client, 'getDocumentInfo', { documentId: 'doc-1' });
      assert.equal(res.isError, false);
      assert.ok(res.content[0].text.includes('My Document'));
    });

    it('validation error', async () => {
      const res = await callTool(ctx.client, 'getDocumentInfo', {});
      assert.equal(res.isError, true);
    });
  });
});
