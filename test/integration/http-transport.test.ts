import assert from 'node:assert/strict';
import { describe, it, before, after, mock } from 'node:test';
import http from 'node:http';
import type { Server as HttpServer } from 'node:http';
import { google } from 'googleapis';
import { createAllMocks } from '../helpers/mock-google-apis.js';
import { setTimeout as delay } from 'node:timers/promises';

let _serverModule: any = null;

async function getServerModule() {
  if (!_serverModule) {
    _serverModule = await import('../../src/index.js');
  }
  return _serverModule;
}

const MCP_HEADERS = {
  'Content-Type': 'application/json',
  'Accept': 'application/json, text/event-stream',
};

/** Parse an SSE or JSON response and return the first JSON-RPC message. */
async function parseResponse(res: Response): Promise<any> {
  const contentType = res.headers.get('content-type') || '';
  const text = await res.text();
  if (contentType.includes('text/event-stream')) {
    // Extract the first `data:` line
    for (const line of text.split('\n')) {
      if (line.startsWith('data: ')) {
        return JSON.parse(line.slice(6));
      }
    }
    throw new Error('No data line found in SSE response');
  }
  return JSON.parse(text);
}

async function setupMocks() {
  const mocks = createAllMocks();
  (google as any).drive = mocks.google.drive;
  (google as any).docs = mocks.google.docs;
  (google as any).sheets = mocks.google.sheets;
  (google as any).slides = mocks.google.slides;
  (google as any).calendar = mocks.google.calendar;

  const mod = await getServerModule();
  mod._setAuthClientForTesting({
    request: async () => ({ data: 'mock-auth-request-response' }),
  });
  return mod;
}

async function initializeSession(baseUrl: string): Promise<string> {
  const res = await fetch(`${baseUrl}/mcp`, {
    method: 'POST',
    headers: MCP_HEADERS,
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
      id: 1,
    }),
  });
  assert.equal(res.status, 200);
  const sessionId = res.headers.get('mcp-session-id')!;
  assert.ok(sessionId);
  await res.text();
  return sessionId;
}

function startServer(app: any): Promise<{ httpServer: HttpServer; baseUrl: string }> {
  return new Promise((resolve) => {
    const httpServer = app.listen(0, '127.0.0.1', () => {
      const addr = httpServer.address();
      let baseUrl = '';
      if (addr && typeof addr === 'object') {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve({ httpServer, baseUrl });
    });
  });
}

async function cleanupServer(httpServer: HttpServer, sessions: Map<string, any>) {
  for (const [, session] of sessions) {
    await session.transport.close();
    await session.server.close();
  }
  sessions.clear();
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
}

describe('HTTP transport', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1');
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('responds to initialize POST and returns session ID', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: MCP_HEADERS,
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
        id: 1,
      }),
    });

    assert.equal(res.status, 200);
    const sessionId = res.headers.get('mcp-session-id');
    assert.ok(sessionId, 'response should include mcp-session-id header');

    const body = await parseResponse(res);
    assert.equal(body.jsonrpc, '2.0');
    assert.equal(body.id, 1);
    assert.ok(body.result, 'response should have a result');
    assert.ok(body.result.serverInfo, 'result should contain serverInfo');
    assert.equal(body.result.serverInfo.name, 'google-drive-mcp');
  });

  it('reuses session ID for subsequent requests', async () => {
    // Initialize
    const initRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: MCP_HEADERS,
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
        id: 1,
      }),
    });
    const sessionId = initRes.headers.get('mcp-session-id')!;
    assert.ok(sessionId);
    // Consume init response
    await initRes.text();

    // Send initialized notification
    await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sessionId },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'notifications/initialized',
      }),
    });

    // List tools using same session
    const toolsRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sessionId },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: 2,
      }),
    });

    assert.equal(toolsRes.status, 200);
    const body = await parseResponse(toolsRes);
    assert.equal(body.id, 2);
    assert.ok(Array.isArray(body.result?.tools), 'should return tools array');
    assert.ok(body.result.tools.length > 0, 'should have at least one tool');
  });

  it('returns 400 for non-initialize request without session', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: MCP_HEADERS,
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: 1,
      }),
    });

    assert.equal(res.status, 400);
    const body = await parseResponse(res);
    assert.ok(body.error, 'should have error');
  });

  it('returns 400 for GET without session ID', async () => {
    // No session ID at all is a client protocol error, distinct from
    // "session ID supplied but unknown" which is 404 (spec: client must
    // start a new session).
    const res = await fetch(`${baseUrl}/mcp`);
    assert.equal(res.status, 400);
  });

  it('DELETE closes session and subsequent requests return 404', async () => {
    // Initialize a session
    const initRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: MCP_HEADERS,
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
        id: 1,
      }),
    });
    const sessionId = initRes.headers.get('mcp-session-id')!;
    assert.ok(sessionId);
    await initRes.text();

    // DELETE the session
    const delRes = await fetch(`${baseUrl}/mcp`, {
      method: 'DELETE',
      headers: { 'mcp-session-id': sessionId },
    });
    assert.equal(delRes.status, 200);

    // Subsequent request with terminated session ID must return 404 so the
    // MCP client knows to re-initialize (streamable-HTTP spec).
    const postRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sessionId },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: 2,
      }),
    });
    assert.equal(postRes.status, 404);
  });
});

// ---------------------------------------------------------------------------
// B1. Session isolation
// ---------------------------------------------------------------------------
describe('HTTP transport — session isolation', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1');
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('two sessions work independently', async () => {
    const sidA = await initializeSession(baseUrl);
    const sidB = await initializeSession(baseUrl);
    assert.notEqual(sidA, sidB);

    for (const sid of [sidA, sidB]) {
      const res = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: { ...MCP_HEADERS, 'mcp-session-id': sid },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 2 }),
      });
      assert.equal(res.status, 200);
      const body = await parseResponse(res);
      assert.ok(Array.isArray(body.result?.tools));
    }
  });

  it('deleting one session does not affect the other', async () => {
    const sidA = await initializeSession(baseUrl);
    const sidB = await initializeSession(baseUrl);

    // Delete A
    const delRes = await fetch(`${baseUrl}/mcp`, {
      method: 'DELETE',
      headers: { 'mcp-session-id': sidA },
    });
    assert.equal(delRes.status, 200);

    // B still works
    const bRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sidB },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 3 }),
    });
    assert.equal(bRes.status, 200);

    // A is gone (terminated session ID returns 404)
    const aRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sidA },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 4 }),
    });
    assert.equal(aRes.status, 404);
  });
});

// ---------------------------------------------------------------------------
// B2. Session idle timeout
// ---------------------------------------------------------------------------
describe('HTTP transport — session idle timeout', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1', { sessionIdleTimeoutMs: 50 });
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('idle session is evicted after timeout and request returns 404', async () => {
    const sid = await initializeSession(baseUrl);
    assert.ok(sessions.has(sid));

    await delay(150);

    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sid },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 2 }),
    });
    // 404 tells the MCP client to start a new session (streamable-HTTP spec)
    assert.equal(res.status, 404);
    assert.equal(sessions.has(sid), false);
  });

  it('activity resets the idle timer', async () => {
    const sid = await initializeSession(baseUrl);

    // Wait less than timeout, then send a request to reset timer
    await delay(30);
    const midRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sid },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 2 }),
    });
    assert.equal(midRes.status, 200);
    await midRes.text();

    // Wait again — total time since last activity < timeout
    await delay(30);
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': sid },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 3 }),
    });
    assert.equal(res.status, 200);
    assert.ok(sessions.has(sid));
  });
});

// ---------------------------------------------------------------------------
// B3. Server.close() on shutdown
// ---------------------------------------------------------------------------
describe('HTTP transport — server.close()', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1');
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('DELETE calls server.close()', async () => {
    const sid = await initializeSession(baseUrl);
    const session = sessions.get(sid)!;
    const closeSpy = mock.fn(session.server.close.bind(session.server));
    session.server.close = closeSpy;

    await fetch(`${baseUrl}/mcp`, {
      method: 'DELETE',
      headers: { 'mcp-session-id': sid },
    });

    assert.equal(closeSpy.mock.callCount(), 1);
  });

  it('transport onclose cleans up session from map', async () => {
    const sid = await initializeSession(baseUrl);
    assert.ok(sessions.has(sid));

    const session = sessions.get(sid)!;
    await session.transport.close();

    // onclose handler should have removed it
    assert.equal(sessions.has(sid), false);
  });
});

// ---------------------------------------------------------------------------
// B4. Error handling
// ---------------------------------------------------------------------------
describe('HTTP transport — error handling', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1');
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('POST with invalid JSON returns 400', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream' },
      body: 'not json',
    });
    assert.ok([400, 500].includes(res.status), `expected 400 or 500, got ${res.status}`);
  });

  it('POST with valid JSON-RPC but unknown method (no session) returns 400', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: MCP_HEADERS,
      body: JSON.stringify({ jsonrpc: '2.0', method: 'foo', id: 1 }),
    });
    assert.equal(res.status, 400);
    const body = await parseResponse(res);
    assert.ok(body.error);
  });

  it('DELETE with non-existent session ID is idempotent (200)', async () => {
    // DELETE is idempotent; returning 200 lets clients reconciling state on
    // shutdown or after a server-side idle timeout proceed without errors.
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'DELETE',
      headers: { 'mcp-session-id': 'non-existent-uuid' },
    });
    assert.equal(res.status, 200);
  });

  it('GET with non-existent session ID returns 404', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'GET',
      headers: { 'mcp-session-id': 'non-existent-uuid' },
    });
    assert.equal(res.status, 404);
  });

  it('POST with non-existent session ID returns 404 (not 400)', async () => {
    // The reconnect bug: claude.ai retries with a stale session ID after the
    // idle timer expires server-side. 400 leaves the client confused; 404 tells
    // it to re-initialize transparently.
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': 'non-existent-uuid' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', params: {}, id: 1 }),
    });
    assert.equal(res.status, 404);
  });

  it('POST initialize with a stale Mcp-Session-Id is still rejected (404)', async () => {
    // A client may retry an initialize while still carrying its stale session
    // header. We require the client to drop the header on init (or omit it);
    // returning 404 makes the client re-initialize cleanly without us
    // implicitly recycling a client-supplied sid.
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { ...MCP_HEADERS, 'mcp-session-id': 'previously-deleted-uuid' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0.0' } },
        id: 1,
      }),
    });
    assert.equal(res.status, 404);
  });
});

// ---------------------------------------------------------------------------
// B5. DNS rebinding protection
// ---------------------------------------------------------------------------
describe('HTTP transport — DNS rebinding protection', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;
  let port: number;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1');
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
    const addr = httpServer.address();
    port = (addr && typeof addr === 'object') ? addr.port : 0;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('request with spoofed Host header is rejected', async () => {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } },
      id: 1,
    });
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: '/mcp',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream',
          'Host': 'evil.com',
          'Content-Length': Buffer.byteLength(body),
        },
      }, (res) => {
        res.resume();
        resolve(res.statusCode!);
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    assert.equal(status, 403);
  });

  it('request with correct Host header succeeds', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: MCP_HEADERS,
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } },
        id: 1,
      }),
    });
    assert.equal(res.status, 200);
  });
});

// ---------------------------------------------------------------------------
// B6. Trust proxy. Required for Cloud Run + GCLB so X-Forwarded-For is
// honored. Without it, express-rate-limit emits ValidationError and keys all
// requests by the LB IP (one shared rate-limit bucket for every user).
// Value must be a hop count (2 here), not `true`, because GCLB appends to
// inbound XFF so a client-spoofed leftmost entry would otherwise be req.ip.
// ---------------------------------------------------------------------------
describe('HTTP transport — trust proxy', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;
  let app: any;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1');
    sessions = result.sessions;
    app = result.app;
    // Mount a probe route AFTER createHttpApp so it inherits the trust-proxy
    // setting. This lets us verify behavior (req.ip resolution), not just the
    // setter value.
    app.get('/__probe_ip', (req: any, res: any) => {
      res.json({ ip: req.ip, ips: req.ips });
    });
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('trust proxy is set to exactly 2 hops (GCLB + Cloud Run frontend)', async () => {
    // Stripping fewer hops than the actual chain leaks the LB IP as req.ip
    // (one shared rate-limit bucket). Trusting more, or `true`, lets a
    // client spoof its IP via X-Forwarded-For. Lock the value at 2.
    assert.equal(app.get('trust proxy'), 2);
  });

  it('req.ip resolves to the GCLB-attested client and ignores a spoofed leftmost XFF entry', async () => {
    // Express's `trust proxy: n` counts the socket peer as the first trusted
    // hop and then trusts n-1 more from the rightmost XFF entries. With n=2,
    // socket + the rightmost XFF entry (the LB hop) are trusted; the next
    // leftward XFF entry is req.ip.
    //
    // Production XFF after GCLB looks like: "<client>, <lb-ip>".
    // We simulate that here, with an additional client-supplied spoofed
    // prefix that GCLB would just append to. trust proxy: 2 must NOT pick the
    // leftmost (spoofed) value. All IPs are RFC 5737 documentation ranges so
    // proxy-addr parses them as valid IPs and the test does not depend on
    // version-specific non-IP token handling.
    const res = await fetch(`${baseUrl}/__probe_ip`, {
      headers: {
        'X-Forwarded-For': '203.0.113.99, 198.51.100.7, 192.0.2.1',
      },
    });
    const body = await res.json() as { ip: string; ips: string[] };
    // The leftmost (spoofed 203.0.113.99) must NOT be picked.
    assert.equal(body.ip, '198.51.100.7',
      `req.ip should be the LB-attested client (198.51.100.7), got ${body.ip}`);
  });

  it('honors explicit trustProxyHops option (overrides default)', async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1', { trustProxyHops: 5 });
    assert.equal(result.app.get('trust proxy'), 5);
  });

  it('honors MCP_TRUST_PROXY_HOPS env var when option is not set', async () => {
    const prev = process.env.MCP_TRUST_PROXY_HOPS;
    process.env.MCP_TRUST_PROXY_HOPS = '3';
    try {
      const mod = await setupMocks();
      const result = mod.createHttpApp('127.0.0.1');
      assert.equal(result.app.get('trust proxy'), 3);
    } finally {
      if (prev === undefined) delete process.env.MCP_TRUST_PROXY_HOPS;
      else process.env.MCP_TRUST_PROXY_HOPS = prev;
    }
  });

  it('falls back to default (2) when env var is invalid', async () => {
    const prev = process.env.MCP_TRUST_PROXY_HOPS;
    process.env.MCP_TRUST_PROXY_HOPS = 'not-a-number';
    try {
      const mod = await setupMocks();
      const result = mod.createHttpApp('127.0.0.1');
      assert.equal(result.app.get('trust proxy'), 2);
    } finally {
      if (prev === undefined) delete process.env.MCP_TRUST_PROXY_HOPS;
      else process.env.MCP_TRUST_PROXY_HOPS = prev;
    }
  });
});

// ---------------------------------------------------------------------------
// B7. server.close() symmetry — each session gets its own Server instance
// ---------------------------------------------------------------------------
describe('HTTP transport — server instance uniqueness', () => {
  let httpServer: HttpServer;
  let baseUrl: string;
  let sessions: Map<string, any>;

  before(async () => {
    const mod = await setupMocks();
    const result = mod.createHttpApp('127.0.0.1');
    sessions = result.sessions;
    const started = await startServer(result.app);
    httpServer = started.httpServer;
    baseUrl = started.baseUrl;
  });

  after(async () => {
    await cleanupServer(httpServer, sessions);
  });

  it('each HTTP session gets its own Server instance', async () => {
    const sidA = await initializeSession(baseUrl);
    const sidB = await initializeSession(baseUrl);

    const serverA = sessions.get(sidA)!.server;
    const serverB = sessions.get(sidB)!.server;
    assert.notEqual(serverA, serverB);
  });
});
