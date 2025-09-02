# Build stage
FROM node:23-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM node:23-slim AS production
WORKDIR /app
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/build ./build
COPY --from=builder /app/patches ./patches
# Remove dev dependencies and cache
RUN npm ci --omit=dev && npm cache clean --force

# TODO: see https://github.com/Azure/azure-sdk-for-js/issues/35466
RUN npm run patch-package

# Use a non-root user for security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
USER appuser
ENV DEBUG="*"
CMD ["node", "./build/index.js"]
