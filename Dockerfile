FROM node:22-slim

WORKDIR /app

COPY package*.json ./

RUN npm ci --only=production --ignore-scripts

COPY dist ./dist

ENV NODE_ENV=production

# Cloud Run: HTTP transport on Cloud Run's $PORT, bound to all interfaces.
# `start` (no flags) picks these up from MCP_TRANSPORT / MCP_HTTP_PORT.
ENV MCP_TRANSPORT=http
ENV MCP_HTTP_HOST=0.0.0.0

# Legacy config paths — kept so stdio mode still works if someone docker-runs
# this image with --transport stdio (unusual).
ENV GOOGLE_DRIVE_OAUTH_CREDENTIALS=/config/gcp-oauth.keys.json
ENV GOOGLE_DRIVE_MCP_TOKEN_PATH=/config/tokens.json

RUN mkdir -p /config
RUN chmod +x dist/index.js

USER node

ENTRYPOINT ["node", "dist/index.js"]
