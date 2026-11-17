FROM node:22-bookworm-slim
ARG ROLE
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ${ROLE}/package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY ${ROLE}/ ./
COPY infra/bootstrap.mjs /app/bootstrap.mjs
COPY worker/protection.mjs /app/transport.mjs
COPY auth/ /auth/
COPY ui/ /ui/
COPY .generated/certs/demo-ca.crt /app/certs/demo-ca.crt
COPY .generated/deploy/ /app/deploy/
USER node
EXPOSE 8443
CMD ["node", "bootstrap.mjs"]
