import assert from 'node:assert/strict';
import { describe, it, before, after, beforeEach } from 'node:test';
import { setupTestServer, callTool, type TestContext } from '../helpers/setup-server.js';

describe('Drive Labels tools', () => {
  let ctx: TestContext;

  before(async () => { ctx = await setupTestServer(); });
  after(async () => { await ctx.cleanup(); });
  beforeEach(() => {
    ctx.mocks.drive.tracker.reset();
    ctx.mocks.driveLabels.tracker.reset();
  });

  // --- listDriveLabels (read the controlled registry) ---
  describe('listDriveLabels', () => {
    const sampleLabel = {
      id: 'LABEL123',
      name: 'labels/LABEL123',
      properties: { title: 'Context' },
      fields: [
        {
          id: 'FIELDArea',
          properties: { displayName: 'Areas' },
          selectionOptions: {
            choices: [
              { id: 'choiceReva', properties: { displayName: 'Reva' } },
              { id: 'choiceCerebro', properties: { displayName: 'Cerebro' } },
            ],
          },
        },
        {
          id: 'FIELDTags',
          properties: { displayName: 'Tags' },
          textOptions: {},
        },
      ],
    };

    it('happy path lists labels, fields, and selection choices', async () => {
      ctx.mocks.driveLabels.service.labels.list._setImpl(async () => ({
        data: { labels: [sampleLabel] },
      }));
      const res = await callTool(ctx.client, 'listDriveLabels', {});
      assert.equal(res.isError, false);
      const text = res.content[0].text;
      assert.ok(text.includes('Context'));
      assert.ok(text.includes('labelId: LABEL123'));
      assert.ok(text.includes('Areas'));
      assert.ok(text.includes('fieldId: FIELDArea'));
      assert.ok(text.includes('type: selection'));
      assert.ok(text.includes('Reva'));
      assert.ok(text.includes('choiceId: choiceReva'));
      assert.ok(text.includes('Tags'));
      assert.ok(text.includes('type: text'));
    });

    it('requests the FULL view, published-only', async () => {
      ctx.mocks.driveLabels.service.labels.list._setImpl(async () => ({ data: { labels: [sampleLabel] } }));
      await callTool(ctx.client, 'listDriveLabels', {});
      const calls = ctx.mocks.driveLabels.tracker.getCalls('labels.list');
      assert.ok(calls.length >= 1);
      const params = calls[calls.length - 1].args[0];
      assert.equal(params.view, 'LABEL_VIEW_FULL');
      assert.equal(params.publishedOnly, true);
    });

    it('handles no labels', async () => {
      ctx.mocks.driveLabels.service.labels.list._setImpl(async () => ({ data: { labels: [] } }));
      const res = await callTool(ctx.client, 'listDriveLabels', {});
      assert.equal(res.isError, false);
      assert.ok(res.content[0].text.includes('No published Drive Labels'));
    });

    it('propagates API error', async () => {
      ctx.mocks.driveLabels.service.labels.list._setImpl(async () => { throw new Error('labels API denied'); });
      const res = await callTool(ctx.client, 'listDriveLabels', {});
      assert.equal(res.isError, true);
      assert.ok(res.content[0].text.includes('labels API denied'));
      ctx.mocks.driveLabels.service.labels.list._resetImpl();
    });
  });

  // --- getFileLabels (read labels on a file) ---
  describe('getFileLabels', () => {
    it('happy path shows applied label field values', async () => {
      ctx.mocks.drive.service.files.listLabels._setImpl(async () => ({
        data: {
          labels: [{
            id: 'LABEL123',
            revisionId: '7',
            fields: {
              FIELDArea: { valueType: 'selection', selection: ['choiceReva'] },
              FIELDTags: { valueType: 'text', text: ['boardy', 'research'] },
            },
          }],
        },
      }));
      const res = await callTool(ctx.client, 'getFileLabels', { fileId: 'file-9' });
      assert.equal(res.isError, false);
      const text = res.content[0].text;
      assert.ok(text.includes('LABEL123'));
      assert.ok(text.includes('FIELDArea'));
      assert.ok(text.includes('choiceReva'));
      assert.ok(text.includes('boardy, research'));
    });

    it('resolves field + choice display names from the taxonomy', async () => {
      ctx.mocks.drive.service.files.listLabels._setImpl(async () => ({
        data: { labels: [{ id: 'LABEL123', revisionId: '7', fields: { FIELDArea: { valueType: 'selection', selection: ['choiceReva'] } } }] },
      }));
      ctx.mocks.driveLabels.service.labels.list._setImpl(async () => ({
        data: { labels: [{
          id: 'LABEL123', name: 'labels/LABEL123', properties: { title: 'Context' },
          fields: [{ id: 'FIELDArea', properties: { displayName: 'Areas' }, selectionOptions: { choices: [{ id: 'choiceReva', properties: { displayName: 'Reva' } }] } }],
        }] },
      }));
      const res = await callTool(ctx.client, 'getFileLabels', { fileId: 'file-9' });
      assert.equal(res.isError, false);
      const text = res.content[0].text;
      assert.ok(text.includes('Context'), 'shows label title');
      assert.ok(text.includes('Areas: Reva'), 'shows field + choice display names');
      ctx.mocks.drive.service.files.listLabels._resetImpl();
      ctx.mocks.driveLabels.service.labels.list._resetImpl();
    });

    it('handles a file with no labels', async () => {
      ctx.mocks.drive.service.files.listLabels._setImpl(async () => ({ data: { labels: [] } }));
      const res = await callTool(ctx.client, 'getFileLabels', { fileId: 'file-9' });
      assert.equal(res.isError, false);
      assert.ok(res.content[0].text.includes('No labels are applied'));
    });

    it('validation error when fileId missing', async () => {
      const res = await callTool(ctx.client, 'getFileLabels', {});
      assert.equal(res.isError, true);
    });
  });

  // --- setFileLabels (modify labels ON the file) ---
  describe('setFileLabels', () => {
    it('builds selection + text + unset field modifications', async () => {
      ctx.mocks.drive.service.files.modifyLabels._setImpl(async () => ({
        data: { modifiedLabels: [{ id: 'LABEL123' }] },
      }));
      const res = await callTool(ctx.client, 'setFileLabels', {
        fileId: 'file-9',
        modifications: [{
          labelId: 'LABEL123',
          fields: [
            { fieldId: 'FIELDArea', selectionValues: ['choiceReva'] },
            { fieldId: 'FIELDTags', textValues: ['boardy'] },
            { fieldId: 'FIELDOld', unset: true },
          ],
        }],
      });
      assert.equal(res.isError, false);

      const calls = ctx.mocks.drive.tracker.getCalls('files.modifyLabels');
      assert.ok(calls.length >= 1);
      const params = calls[calls.length - 1].args[0];
      assert.equal(params.fileId, 'file-9');
      const mods = params.requestBody.labelModifications;
      assert.equal(mods[0].labelId, 'LABEL123');
      const fmods = mods[0].fieldModifications;
      assert.deepEqual(fmods[0], { fieldId: 'FIELDArea', setSelectionValues: ['choiceReva'] });
      assert.deepEqual(fmods[1], { fieldId: 'FIELDTags', setTextValues: ['boardy'] });
      assert.deepEqual(fmods[2], { fieldId: 'FIELDOld', unsetValues: true });
    });

    it('validation error when a field has no values and is not unset', async () => {
      const res = await callTool(ctx.client, 'setFileLabels', {
        fileId: 'file-9',
        modifications: [{ labelId: 'LABEL123', fields: [{ fieldId: 'FIELDArea' }] }],
      });
      assert.equal(res.isError, true);
    });

    it('validation error when modifications empty', async () => {
      const res = await callTool(ctx.client, 'setFileLabels', { fileId: 'file-9', modifications: [] });
      assert.equal(res.isError, true);
    });

    it('propagates API error', async () => {
      ctx.mocks.drive.service.files.modifyLabels._setImpl(async () => { throw new Error('modify denied'); });
      const res = await callTool(ctx.client, 'setFileLabels', {
        fileId: 'file-9',
        modifications: [{ labelId: 'LABEL123', fields: [{ fieldId: 'F', textValues: ['x'] }] }],
      });
      assert.equal(res.isError, true);
      assert.ok(res.content[0].text.includes('modify denied'));
      ctx.mocks.drive.service.files.modifyLabels._resetImpl();
    });
  });
});
