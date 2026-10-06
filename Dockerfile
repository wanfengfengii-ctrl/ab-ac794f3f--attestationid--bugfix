# Satellite attestation gateway - zero npm dependencies (Node built-ins only),
# so there is deliberately no `npm install` layer.
FROM node:22-alpine

WORKDIR /app

# Copy sources first (context is tiny; layout kept explicit on purpose).
COPY package.json ./
COPY src ./src
COPY tools ./tools
COPY test ./test
COPY config ./config

# Writable, durable data directory owned by the unprivileged node user.
RUN mkdir -p /app/data && chown -R node:node /app
USER node

ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/app/data \
    DEVICE_KEYS_FILE=/app/config/device-keys.json

EXPOSE 8080

# Container-level health check drives compose readiness/restart policy and
# lets operators gate deployment on the same endpoint used by monitoring.
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

# Default command runs the API; the "verify" compose service overrides this
# with the one-shot test/build/smoke aggregator.
CMD ["node", "src/server.mjs"]
