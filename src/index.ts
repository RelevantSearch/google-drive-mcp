#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";
import { randomUUID, randomBytes } from 'crypto';
import { google } from "googleapis";
import type { drive_v3, calendar_v3 } from "googleapis";
import { authenticate, AuthServer, initializeOAuth2Client } from './auth.js';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import type { Request, Response } from 'express';
import {
  getExtensionFromFilename,
  escapeDriveQuery,
} from './utils.js';
import type { ToolContext } from './types.js';
import { errorResponse } from './types.js';
import { FirestoreStore } from './auth/firestore-store.js';
import { GoogleOAuth } from './auth/google-oauth.js';
import { McpJwt } from './auth/jwt.js';
import { DriveOAuthProvider } from './auth/provider.js';
import { getUserAccessToken } from './auth/user-token.js';

import * as driveTools from './tools/drive.js';
import * as docsTools from './tools/docs.js';
import * as sheetsTools from './tools/sheets.js';
import * as slidesTools from './tools/slides.js';
import * as calendarTools from './tools/calendar.js';

interface AuthDeps {
  provider: DriveOAuthProvider;
  store: FirestoreStore;
  googleOAuth: GoogleOAuth;
  publicUrl: string;
  allowedHostedDomain: string;
  scopes: string[];
}

// Cached service instances — only recreated when authClient changes
let _drive: drive_v3.Drive | null = null;
let _calendar: calendar_v3.Calendar | null = null;
let _lastAuthClient: any = null;

function getDrive(): drive_v3.Drive {
  if (!authClient) throw new Error('Authentication required');
  if (_drive && _lastAuthClient === authClient) return _drive;
  _drive = google.drive({ version: 'v3', auth: authClient });
  log('Drive service created');
  return _drive;
}

function getCalendar(): calendar_v3.Calendar {
  if (!authClient) throw new Error('Authentication required');
  if (_calendar && _lastAuthClient === authClient) return _calendar;
  _calendar = google.calendar({ version: 'v3', auth: authClient });
  log('Calendar service created');
  return _calendar;
}

const FOLDER_MIME_TYPE = 'application/vnd.google-apps.folder';

// Global auth client - will be initialized on first use
let authClient: any = null;
let authenticationPromise: Promise<any> | null = null;

// Get package version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJsonPath = join(__dirname, '..', 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
const VERSION = packageJson.version;

// -----------------------------------------------------------------------------
// LOGGING UTILITY
// -----------------------------------------------------------------------------
function log(message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logMessage = data
    ? `[${timestamp}] ${message}: ${JSON.stringify(data)}`
    : `[${timestamp}] ${message}`;
  console.error(logMessage);
}

// -----------------------------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------------------------

async function resolvePathOn(drive: drive_v3.Drive, pathStr: string): Promise<string> {
  if (!pathStr || pathStr === '/') return 'root';

  const parts = pathStr.replace(/^\/+|\/+$/g, '').split('/');
  let currentFolderId: string = 'root';

  for (const part of parts) {
    if (!part) continue;
    const escapedPart = escapeDriveQuery(part);
    const response = await drive.files.list({
      q: `'${currentFolderId}' in parents and name = '${escapedPart}' and mimeType = '${FOLDER_MIME_TYPE}' and trashed = false`,
      fields: 'files(id)',
      spaces: 'drive',
      includeItemsFromAllDrives: true,
      supportsAllDrives: true
    });

    if (!response.data.files?.length) {
      const folderMetadata = {
        name: part,
        mimeType: FOLDER_MIME_TYPE,
        parents: [currentFolderId]
      };
      const folder = await drive.files.create({
        requestBody: folderMetadata,
        fields: 'id',
        supportsAllDrives: true
      });

      if (!folder.data.id) {
        throw new Error(`Failed to create intermediate folder: ${part}`);
      }

      currentFolderId = folder.data.id;
    } else {
      currentFolderId = response.data.files[0].id!;
    }
  }

  return currentFolderId;
}

async function resolveFolderIdOn(drive: drive_v3.Drive, input: string | undefined): Promise<string> {
  if (!input) return 'root';
  if (input.startsWith('/')) return resolvePathOn(drive, input);
  return input;
}

async function checkFileExistsOn(drive: drive_v3.Drive, name: string, parentFolderId: string = 'root'): Promise<string | null> {
  try {
    const escapedName = escapeDriveQuery(name);
    const query = `name = '${escapedName}' and '${parentFolderId}' in parents and trashed = false`;

    const res = await drive.files.list({
      q: query,
      fields: 'files(id, name, mimeType)',
      pageSize: 1,
      includeItemsFromAllDrives: true,
      supportsAllDrives: true
    });

    if (res.data.files && res.data.files.length > 0) {
      return res.data.files[0].id || null;
    }
    return null;
  } catch (error) {
    log('Error checking file existence:', error);
    return null;
  }
}

// Global wrappers — used by stdio mode where the process-level authClient is set
// by the existing `authenticate()` flow. HTTP mode never calls these.
const resolvePath = (pathStr: string) => resolvePathOn(getDrive(), pathStr);
const resolveFolderId = (input: string | undefined) => resolveFolderIdOn(getDrive(), input);
const checkFileExists = (name: string, parentFolderId: string = 'root') =>
  checkFileExistsOn(getDrive(), name, parentFolderId);

function validateTextFileExtension(name: string) {
  const ext = getExtensionFromFilename(name);
  if (!['txt', 'md'].includes(ext)) {
    throw new Error("File name must end with .txt or .md for text files.");
  }
}

// -----------------------------------------------------------------------------
// AUTHENTICATION HELPER
// -----------------------------------------------------------------------------
async function ensureAuthenticated() {
  if (authClient) return;

  if (authenticationPromise) {
    log('Authentication already in progress, waiting...');
    authClient = await authenticationPromise;
    return;
  }

  log('Initializing authentication');
  authenticationPromise = authenticate();
  try {
    authClient = await authenticationPromise;
    log('Authentication complete');
  } finally {
    authenticationPromise = null;
  }
}

// -----------------------------------------------------------------------------
// DOMAIN MODULES
// -----------------------------------------------------------------------------
const domainModules = [driveTools, docsTools, sheetsTools, slidesTools, calendarTools];

function buildToolContext(): ToolContext {
  return {
    authClient,
    google,
    getDrive,
    getCalendar,
    log,
    resolvePath,
    resolveFolderId,
    checkFileExists,
    validateTextFileExtension,
  };
}

/**
 * Build a per-request ToolContext backed by a user's Google access token.
 *
 * `authInfo.extra` carries `{ userId, email }` from `DriveOAuthProvider.verifyAccessToken`.
 * We resolve the Google access token via cache → Firestore → refresh, then build an
 * ephemeral auth client that `googleapis` can use for this request's lifetime.
 */
function buildUserToolContext(authInfo: AuthInfo, deps: AuthDeps): ToolContext {
  const userId = (authInfo.extra?.userId as string) ?? authInfo.clientId;
  const email = (authInfo.extra?.email as string) ?? '';

  const userAuthClient = {
    getAccessToken: async () => {
      const token = await getUserAccessToken(userId, deps.store, deps.googleOAuth);
      return { token };
    },
  };

  let drive: drive_v3.Drive | null = null;
  let calendar: calendar_v3.Calendar | null = null;
  const lazyDrive = () => {
    if (!drive) drive = google.drive({ version: 'v3', auth: userAuthClient as any });
    return drive;
  };

  return {
    authClient: userAuthClient,
    google,
    getDrive: lazyDrive,
    getCalendar: () => {
      if (!calendar) calendar = google.calendar({ version: 'v3', auth: userAuthClient as any });
      return calendar;
    },
    log,
    resolvePath: (pathStr) => resolvePathOn(lazyDrive(), pathStr),
    resolveFolderId: (input) => resolveFolderIdOn(lazyDrive(), input),
    checkFileExists: (name, parentFolderId) => checkFileExistsOn(lazyDrive(), name, parentFolderId),
    validateTextFileExtension,
    user: {
      sub: userId,
      email,
      scope: authInfo.scopes?.join(' ') ?? '',
    },
  };
}

// -----------------------------------------------------------------------------
// SERVER FACTORY
// -----------------------------------------------------------------------------

function createMcpServer(authDeps?: AuthDeps): Server {
  const s = new Server(
    {
      name: "google-drive-mcp",
      version: VERSION,
    },
    {
      capabilities: {
        resources: {},
        tools: {},
      },
    },
  );

  /**
   * Build a ToolContext for this request. In HTTP (auth) mode, `extra.authInfo`
   * carries the validated JWT claims and we build a per-user context. In stdio
   * mode, we fall back to the shared process-level authClient.
   */
  async function contextFor(extra: { authInfo?: AuthInfo } | undefined): Promise<ToolContext> {
    if (authDeps && extra?.authInfo) {
      return buildUserToolContext(extra.authInfo, authDeps);
    }
    await ensureAuthenticated();
    return buildToolContext();
  }

  s.setRequestHandler(ListResourcesRequestSchema, async (request, extra) => {
    log('Handling ListResources request', { params: request.params });
    const ctx = await contextFor(extra);
    const pageSize = 10;
    const params: {
      pageSize: number,
      fields: string,
      pageToken?: string,
      q: string,
      includeItemsFromAllDrives: boolean,
      supportsAllDrives: boolean
    } = {
      pageSize,
      fields: "nextPageToken, files(id, name, mimeType)",
      q: `trashed = false`,
      includeItemsFromAllDrives: true,
      supportsAllDrives: true
    };

    if (request.params?.cursor) {
      params.pageToken = request.params.cursor;
    }

    const res = await ctx.getDrive().files.list(params);
    log('Listed files', { count: res.data.files?.length });
    const files = res.data.files || [];

    return {
      resources: files.map((file: drive_v3.Schema$File) => ({
        uri: `gdrive:///${file.id}`,
        mimeType: file.mimeType || 'application/octet-stream',
        name: file.name || 'Untitled',
      })),
      nextCursor: res.data.nextPageToken,
    };
  });

  s.setRequestHandler(ReadResourceRequestSchema, async (request, extra) => {
    log('Handling ReadResource request', { uri: request.params.uri });
    const ctx = await contextFor(extra);
    const fileId = request.params.uri.replace("gdrive:///", "");

    const file = await ctx.getDrive().files.get({
      fileId,
      fields: "mimeType",
      supportsAllDrives: true
    });
    const mimeType = file.data.mimeType;

    if (!mimeType) {
      throw new Error("File has no MIME type.");
    }

    if (mimeType.startsWith("application/vnd.google-apps")) {
      let exportMimeType;
      switch (mimeType) {
        case "application/vnd.google-apps.document": exportMimeType = "text/markdown"; break;
        case "application/vnd.google-apps.spreadsheet": exportMimeType = "text/csv"; break;
        case "application/vnd.google-apps.presentation": exportMimeType = "text/plain"; break;
        case "application/vnd.google-apps.drawing": exportMimeType = "image/png"; break;
        default: exportMimeType = "text/plain"; break;
      }

      const res = await ctx.getDrive().files.export(
        { fileId, mimeType: exportMimeType },
        { responseType: "text" },
      );

      log('Successfully read resource', { fileId, mimeType });
      return {
        contents: [
          {
            uri: request.params.uri,
            mimeType: exportMimeType,
            text: res.data,
          },
        ],
      };
    } else {
      const res = await ctx.getDrive().files.get(
        { fileId, alt: "media", supportsAllDrives: true },
        { responseType: "arraybuffer" },
      );
      const contentMime = mimeType || "application/octet-stream";

      if (contentMime.startsWith("text/") || contentMime === "application/json") {
        return {
          contents: [
            {
              uri: request.params.uri,
              mimeType: contentMime,
              text: Buffer.from(res.data as ArrayBuffer).toString("utf-8"),
            },
          ],
        };
      } else {
        return {
          contents: [
            {
              uri: request.params.uri,
              mimeType: contentMime,
              blob: Buffer.from(res.data as ArrayBuffer).toString("base64"),
            },
          ],
        };
      }
    }
  });

  s.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: domainModules.flatMap(m => m.toolDefinitions),
    };
  });

  s.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    log('Handling tool request', { tool: request.params.name });
    const ctx = await contextFor(extra);

    try {
      for (const mod of domainModules) {
        const result = await mod.handleTool(request.params.name, request.params.arguments ?? {}, ctx);
        if (result !== null) return result;
      }
      return errorResponse("Tool not found");
    } catch (error) {
      log('Error in tool request handler', { error: (error as Error).message });
      return errorResponse((error as Error).message);
    }
  });

  return s;
}

// Module-level server instance (used by stdio mode and tests)
const server = createMcpServer();

// -----------------------------------------------------------------------------
// CLI FUNCTIONS
// -----------------------------------------------------------------------------

function showHelp(): void {
  console.log(`
Google Drive MCP Server v${VERSION}

Usage:
  npx @yourusername/google-drive-mcp [command] [options]

Commands:
  auth     Run the authentication flow
  start    Start the MCP server (default)
  version  Show version information
  help     Show this help message

Transport Options:
  --transport <stdio|http>   Transport mode (default: stdio)
  --port <number>            HTTP listen port (default: 3100)
  --host <address>           HTTP bind address (default: 127.0.0.1)

Examples:
  npx @yourusername/google-drive-mcp auth
  npx @yourusername/google-drive-mcp start
  npx @yourusername/google-drive-mcp start --transport http --port 3100
  npx @yourusername/google-drive-mcp version
  npx @yourusername/google-drive-mcp

Environment Variables:
  GOOGLE_DRIVE_OAUTH_CREDENTIALS        Path to OAuth credentials file
  GOOGLE_DRIVE_MCP_TOKEN_PATH           Path to store authentication tokens
  GOOGLE_DRIVE_MCP_AUTH_PORT            Starting port for OAuth callback server (default: 3000, uses 5 consecutive ports)

  Transport Configuration:
  MCP_TRANSPORT                         Transport mode: stdio or http (default: stdio)
  MCP_HTTP_PORT                         HTTP listen port (default: 3100)
  MCP_HTTP_HOST                         HTTP bind address (default: 127.0.0.1)

  Service Account Mode:
  GOOGLE_APPLICATION_CREDENTIALS        Path to service account JSON key file

  External OAuth Token Mode:
  GOOGLE_DRIVE_MCP_ACCESS_TOKEN         Pre-obtained Google OAuth access token
  GOOGLE_DRIVE_MCP_REFRESH_TOKEN        Refresh token for auto-refresh (optional)
  GOOGLE_DRIVE_MCP_CLIENT_ID            OAuth client ID (required with refresh token)
  GOOGLE_DRIVE_MCP_CLIENT_SECRET        OAuth client secret (required with refresh token)
`);
}

function showVersion(): void {
  console.log(`Google Drive MCP Server v${VERSION}`);
}

async function runAuthServer(): Promise<void> {
  try {
    const oauth2Client = await initializeOAuth2Client();
    const authServerInstance = new AuthServer(oauth2Client);
    const success = await authServerInstance.start(true);

    if (!success && !authServerInstance.authCompletedSuccessfully) {
      const { start, end } = authServerInstance.portRange;
      console.error(
        `Authentication failed. Could not start server or validate existing tokens. Check port availability (${start}-${end}) and try again.`
      );
      process.exit(1);
    } else if (authServerInstance.authCompletedSuccessfully) {
      console.log("Authentication successful.");
      process.exit(0);
    }

    console.log(
      "Authentication server started. Please complete the authentication in your browser..."
    );

    const intervalId = setInterval(async () => {
      if (authServerInstance.authCompletedSuccessfully) {
        clearInterval(intervalId);
        await authServerInstance.stop();
        console.log("Authentication completed successfully!");
        process.exit(0);
      }
    }, 1000);
  } catch (error) {
    console.error("Authentication failed:", error);
    process.exit(1);
  }
}

// -----------------------------------------------------------------------------
// MAIN EXECUTION
// -----------------------------------------------------------------------------

interface CliArgs {
  command: string | undefined;
  transport: 'stdio' | 'http';
  httpPort: number;
  httpHost: string;
}

function parseCliArgs(): CliArgs {
  const args = process.argv.slice(2);
  let command: string | undefined;
  let transport: string | undefined;
  let httpPort: string | undefined;
  let httpHost: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--version' || arg === '-v' || arg === '--help' || arg === '-h') {
      command = arg;
      continue;
    }

    if (arg === '--transport' && i + 1 < args.length) {
      transport = args[++i];
      continue;
    }
    if (arg === '--port' && i + 1 < args.length) {
      httpPort = args[++i];
      continue;
    }
    if (arg === '--host' && i + 1 < args.length) {
      httpHost = args[++i];
      continue;
    }

    if (!command && !arg.startsWith('--')) {
      command = arg;
      continue;
    }
  }

  const resolvedTransport = transport || process.env.MCP_TRANSPORT || 'stdio';
  if (resolvedTransport !== 'stdio' && resolvedTransport !== 'http') {
    console.error(`Invalid transport: ${resolvedTransport}. Must be "stdio" or "http".`);
    process.exit(1);
  }

  // Cloud Run injects $PORT (default 8080) — honour it as the last fallback.
  const resolvedPort = parseInt(
    httpPort || process.env.MCP_HTTP_PORT || process.env.PORT || '3100',
    10,
  );
  if (isNaN(resolvedPort) || resolvedPort < 1 || resolvedPort > 65535) {
    console.error(`Invalid port: ${httpPort || process.env.MCP_HTTP_PORT}. Must be 1-65535.`);
    process.exit(1);
  }

  return {
    command,
    transport: resolvedTransport,
    httpPort: resolvedPort,
    httpHost: httpHost || process.env.MCP_HTTP_HOST || '127.0.0.1',
  };
}

async function main() {
  const args = parseCliArgs();

  switch (args.command) {
    case "auth":
      await runAuthServer();
      break;
    case "start":
    case undefined:
      if (args.transport === 'http') {
        await startHttpTransport(args);
      } else {
        await startStdioTransport();
      }
      break;
    case "version":
    case "--version":
    case "-v":
      showVersion();
      break;
    case "help":
    case "--help":
    case "-h":
      showHelp();
      break;
    default:
      console.error(`Unknown command: ${args.command}`);
      showHelp();
      process.exit(1);
  }
}

async function startStdioTransport(): Promise<void> {
  try {
    console.error("Starting Google Drive MCP server (stdio)...");
    const transport = new StdioServerTransport();
    await server.connect(transport);
    log('Server started successfully');

    process.on("SIGINT", async () => {
      await server.close();
      process.exit(0);
    });
    process.on("SIGTERM", async () => {
      await server.close();
      process.exit(0);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

interface HttpSession {
  transport: StreamableHTTPServerTransport;
  server: Server;
}

/**
 * Create an Express app with MCP Streamable HTTP routes.
 * Shared by production (startHttpTransport) and tests.
 */
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

interface CreateHttpAppOptions {
  sessionIdleTimeoutMs?: number;
  /**
   * When provided, the app is configured as an MCP OAuth 2.1 authorization
   * server: `/register`, `/authorize`, `/token`, and discovery endpoints are
   * served by `mcpAuthRouter`, `/oauth/google/callback` is handled locally,
   * and `/mcp` routes are gated by `requireBearerAuth`.
   */
  authDeps?: AuthDeps;
}

function createHttpApp(host: string, options?: CreateHttpAppOptions) {
  const idleTimeoutMs = options?.sessionIdleTimeoutMs ?? SESSION_IDLE_TIMEOUT_MS;
  const authDeps = options?.authDeps;
  const app = createMcpExpressApp({ host });
  const sessions = new Map<string, HttpSession>();
  const sessionTimers = new Map<string, ReturnType<typeof setTimeout>>();

  if (authDeps) {
    const issuerUrl = new URL(authDeps.publicUrl);
    app.use(mcpAuthRouter({
      provider: authDeps.provider,
      issuerUrl,
      scopesSupported: authDeps.scopes,
      resourceName: 'Google Drive MCP (Relevant Search)',
    }));

    app.get('/oauth/google/callback', async (req: Request, res: Response) => {
      try {
        await handleGoogleCallback(req, res, authDeps);
      } catch (err) {
        log('Google callback error', { error: (err as Error).message });
        if (!res.headersSent) {
          res.status(500).send(`Authentication failed: ${(err as Error).message}`);
        }
      }
    });
  }

  const bearerMiddleware = authDeps
    ? requireBearerAuth({ verifier: authDeps.provider })
    : null;

  function resetSessionTimer(sid: string) {
    const existing = sessionTimers.get(sid);
    if (existing) clearTimeout(existing);
    sessionTimers.set(sid, setTimeout(async () => {
      const session = sessions.get(sid);
      if (session) {
        log(`Session idle timeout: ${sid}`);
        await session.transport.close();
        await session.server.close();
        sessions.delete(sid);
      }
      sessionTimers.delete(sid);
    }, idleTimeoutMs));
  }

  function clearSessionTimer(sid: string) {
    const timer = sessionTimers.get(sid);
    if (timer) {
      clearTimeout(timer);
      sessionTimers.delete(sid);
    }
  }

  const mcpHandlers = bearerMiddleware ? [bearerMiddleware] : [];

  app.post('/mcp', ...mcpHandlers, async (req, res) => {
    try {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      // If we have an existing session, delegate to it
      if (sessionId && sessions.has(sessionId)) {
        const session = sessions.get(sessionId)!;
        resetSessionTimer(sessionId);
        await session.transport.handleRequest(req, res, req.body);
        return;
      }

      // New session: only accept initialize requests
      if (!isInitializeRequest(req.body)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32600, message: 'Bad Request: expected initialize request or valid session ID' },
          id: null,
        });
        return;
      }

      // Create a new session
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });
      const sessionServer = createMcpServer(authDeps);

      await sessionServer.connect(transport);

      // Track the session once we know its ID (set after handleRequest processes init)
      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) {
          clearSessionTimer(sid);
          sessions.delete(sid);
          log(`Session closed: ${sid}`);
        }
      };

      await transport.handleRequest(req, res, req.body);

      const sid = transport.sessionId;
      if (sid) {
        sessions.set(sid, { transport, server: sessionServer });
        resetSessionTimer(sid);
        log(`New session created: ${sid}`);
      }
    } catch (error) {
      log('Error handling POST /mcp', { error: (error as Error).message });
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: null,
        });
      }
    }
  });

  app.get('/mcp', ...mcpHandlers, async (req, res) => {
    try {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32600, message: 'Bad Request: missing or invalid session ID' },
          id: null,
        });
        return;
      }
      const session = sessions.get(sessionId)!;
      resetSessionTimer(sessionId);
      await session.transport.handleRequest(req, res);
    } catch (error) {
      log('Error handling GET /mcp', { error: (error as Error).message });
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: null,
        });
      }
    }
  });

  app.delete('/mcp', ...mcpHandlers, async (req, res) => {
    try {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32600, message: 'Bad Request: missing or invalid session ID' },
          id: null,
        });
        return;
      }
      const session = sessions.get(sessionId)!;
      await session.transport.close();
      await session.server.close();
      sessions.delete(sessionId);
      res.status(200).end();
    } catch (error) {
      log('Error handling DELETE /mcp', { error: (error as Error).message });
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: null,
        });
      }
    }
  });

  return { app, sessions };
}

/**
 * Build the OAuth auth dependencies from required env vars. Returns undefined
 * when any are missing so local HTTP runs (no Firestore, no Google OAuth) keep
 * working — the resulting app runs with no bearer guard.
 */
function buildAuthDepsFromEnv(): AuthDeps | undefined {
  const publicUrl = process.env.PUBLIC_URL;
  const signingKey = process.env.MCP_SIGNING_KEY;
  const googleClientId = process.env.GOOGLE_OAUTH_CLIENT_ID;
  const googleClientSecret = process.env.GOOGLE_OAUTH_CLIENT_SECRET;

  if (!publicUrl || !signingKey || !googleClientId || !googleClientSecret) {
    log('Auth env vars not set — running HTTP without OAuth guard');
    return undefined;
  }

  const scopes = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/documents',
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/presentations',
    'https://www.googleapis.com/auth/calendar',
    'openid',
    'email',
    'profile',
  ];

  const store = new FirestoreStore();
  const googleOAuth = new GoogleOAuth({
    clientId: googleClientId,
    clientSecret: googleClientSecret,
    redirectUri: `${publicUrl.replace(/\/$/, '')}/oauth/google/callback`,
  });
  const jwt = new McpJwt(signingKey);
  const provider = new DriveOAuthProvider(store, googleOAuth, jwt, publicUrl, scopes);

  return {
    provider,
    store,
    googleOAuth,
    publicUrl,
    allowedHostedDomain: process.env.ALLOWED_HOSTED_DOMAIN ?? 'relevantsearch.com',
    scopes,
  };
}

/**
 * Handles `/oauth/google/callback`.
 *
 * Google redirects here with `?code=...&state=...`. We look up the in-flight
 * pending authorization by Google's state (stored in `DriveOAuthProvider.authorize`),
 * exchange the code for tokens, verify the hosted domain (`hd` claim or email
 * suffix), persist the user's tokens, and mint an authorization code that
 * claude.ai can redeem at `/token`.
 */
async function handleGoogleCallback(req: Request, res: Response, deps: AuthDeps): Promise<void> {
  const code = req.query.code as string | undefined;
  const googleState = req.query.state as string | undefined;
  const error = req.query.error as string | undefined;

  if (error) {
    res.status(400).send(`Google OAuth error: ${error}`);
    return;
  }
  if (!code || !googleState) {
    res.status(400).send('Missing code or state');
    return;
  }

  const pending = await deps.store.getPendingAuthorization(googleState);
  if (!pending) {
    res.status(400).send('Unknown or expired state');
    return;
  }

  // Consume the pending record — one-shot use.
  await deps.store.deletePendingAuthorization(googleState);

  const tokens = await deps.googleOAuth.exchangeCode(code, pending.google_pkce_verifier);
  if (!tokens.id_token) {
    res.status(400).send('Google did not return an id_token — cannot identify user');
    return;
  }

  // Decode id_token payload without verification. The token comes from a direct
  // server-to-server exchange with Google (TLS), so we trust the transport.
  const payload = decodeIdTokenPayload(tokens.id_token);
  const userId = String(payload.sub ?? '');
  const email = String(payload.email ?? '');
  const hd = typeof payload.hd === 'string' ? payload.hd : undefined;

  if (!userId || !email) {
    res.status(400).send('Google id_token missing sub/email claim');
    return;
  }
  const domainOk = hd === deps.allowedHostedDomain || email.endsWith(`@${deps.allowedHostedDomain}`);
  if (!domainOk) {
    res.status(403).send(`Access limited to @${deps.allowedHostedDomain} accounts`);
    return;
  }

  const nowSec = Math.floor(Date.now() / 1000);
  await deps.store.saveUserTokens({
    user_id: userId,
    google_access_token: tokens.access_token,
    google_refresh_token: tokens.refresh_token ?? '',
    google_token_expires_at: nowSec + tokens.expires_in,
    email,
    updated_at: new Date(),
  });

  // Mint our authorization code — redeemed by claude.ai at /token.
  const ourCode = randomBytes(32).toString('base64url');
  await deps.store.saveAuthorizationCode(ourCode, {
    claude_code_challenge: pending.claude_code_challenge,
    user_id: userId,
    email,
    google_access_token: tokens.access_token,
    google_refresh_token: tokens.refresh_token ?? '',
    google_token_expires_at: nowSec + tokens.expires_in,
    created_at: new Date(),
  });

  const redirect = new URL(pending.claude_redirect_uri);
  redirect.searchParams.set('code', ourCode);
  if (pending.claude_state) redirect.searchParams.set('state', pending.claude_state);

  log('Google callback completed', { userId, email });
  res.redirect(302, redirect.toString());
}

/** Minimal JWT payload decoder — no signature verification. */
function decodeIdTokenPayload(idToken: string): Record<string, unknown> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed id_token');
  const json = Buffer.from(parts[1], 'base64url').toString('utf-8');
  return JSON.parse(json) as Record<string, unknown>;
}

async function startHttpTransport(args: CliArgs): Promise<void> {
  try {
    const { httpPort, httpHost } = args;
    console.error(`Starting Google Drive MCP server (HTTP on ${httpHost}:${httpPort})...`);

    const authDeps = buildAuthDepsFromEnv();
    const { app, sessions } = createHttpApp(httpHost, { authDeps });

    const httpServer = app.listen(httpPort, httpHost, () => {
      log(`HTTP server listening on ${httpHost}:${httpPort}${authDeps ? ' (auth enabled)' : ''}`);
    });

    const shutdown = async () => {
      log('Shutting down HTTP server...');
      for (const [sid, session] of sessions) {
        await session.transport.close();
        await session.server.close();
        sessions.delete(sid);
      }
      httpServer.close();
      process.exit(0);
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } catch (error) {
    console.error('Failed to start HTTP server:', error);
    process.exit(1);
  }
}

// Export server, factory, and main for testing or potential programmatic use
export { main, server, createMcpServer, createHttpApp };

/** Inject a fake auth client for testing — bypasses authenticate(). */
export function _setAuthClientForTesting(client: any) {
  authClient = client;
  _drive = null;
  _calendar = null;
  _lastAuthClient = null;
}

// Run the CLI (skip when imported by tests)
if (!process.env.MCP_TESTING) {
  main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}
