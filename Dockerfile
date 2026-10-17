# Requires a vendored SDK: run scripts/vendor-local-deps.sh first (CI does), because
# `file:../sdk-ts` does not resolve inside the build context. Goes away once
# @ace-protocol/sdk is published.
FROM node:24.18-alpine AS builder
WORKDIR /app
COPY package*.json ./
COPY vendor ./vendor
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
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/src/server.js"]
