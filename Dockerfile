# Dockerfile for Privex Multi-Platform Detection Engine & Scanner CLI
FROM node:22-alpine AS builder

WORKDIR /app

# Copy root configs & manifests
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/ ./packages/
COPY apps/ ./apps/

# Install dependencies and build shared packages
RUN npm ci
RUN npm run build:web

# Minimal runtime image
FROM node:22-alpine AS runner

WORKDIR /app

LABEL org.opencontainers.image.title="privex" \
      org.opencontainers.image.description="Privex On-Device Threat, Phishing, Scam, and Malware Detection Engine" \
      org.opencontainers.image.url="https://github.com/bhedanikhilkumar-code/Privex" \
      org.opencontainers.image.source="https://github.com/bhedanikhilkumar-code/Privex" \
      org.opencontainers.image.vendor="Privex Security" \
      org.opencontainers.image.licenses="MIT"

ENV NODE_ENV=production

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/apps/web/dist ./web-dist

# Verify node runtime and entrypoint
EXPOSE 8080

CMD ["node", "-e", "console.log('Privex On-Device Threat Detection Engine Container Initialized. Ready for headless scan operations.')"]
