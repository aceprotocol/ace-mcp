FROM node:24.18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:24.18-alpine
RUN apk add --no-cache tini
WORKDIR /app
# Same base image as the builder: its pruned node_modules is the production install.
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/resources ./resources
EXPOSE 3100 9100
USER node
# /health answers only an allowed Host (DNS-rebinding guard): send the first ALLOWED_HOSTS entry.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["node", "-e", "require('node:http').get({ host: '127.0.0.1', port: process.env.PORT || 3100, path: '/health', headers: { host: process.env.ALLOWED_HOSTS.split(',')[0].trim() } }, (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/src/server.js"]
