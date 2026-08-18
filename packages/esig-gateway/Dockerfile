# Assurance Gateway container.
#
# Build from the REPO ROOT (the gateway is a workspace package and needs
# @e-sig/core built from source in the same tree):
#
#   docker build -f packages/esig-gateway/Dockerfile -t esig-assurance-gateway:dev .
#
# Release builds MUST pin the base by digest — handoff §5 requires a
# digest-pinned image, and that has to include what we build ON:
#
#   docker build --build-arg NODE_IMAGE=node:22-bookworm-slim@sha256:<digest> ...
#
# The default below is a mutable tag deliberately: a hard-coded digest here
# would rot silently and be trusted anyway. Pin it in the pipeline, where the
# digest is resolved and recorded per release.
ARG NODE_IMAGE=node:22-bookworm-slim

# ---------- builder ----------
FROM ${NODE_IMAGE} AS builder
WORKDIR /app

# Manifests first so dependency installation caches independently of source.
COPY package.json package-lock.json ./
COPY packages/esig-core/package.json packages/esig-core/
COPY packages/esig-gateway/package.json packages/esig-gateway/
COPY packages/esig-supabase/package.json packages/esig-supabase/
COPY packages/esig-react/package.json packages/esig-react/
COPY packages/esig-uuaid/package.json packages/esig-uuaid/
COPY packages/esig-uaid-exch/package.json packages/esig-uaid-exch/
COPY packages/esig-worm/package.json packages/esig-worm/
COPY packages/esig-hsm-pkcs11/package.json packages/esig-hsm-pkcs11/
COPY examples/quickstart/package.json examples/quickstart/
COPY infra/provisioning/package.json infra/provisioning/

# Chromium is installed in the runtime stage; puppeteer-core downloads nothing.
ENV PUPPETEER_SKIP_DOWNLOAD=1
RUN npm ci --ignore-scripts

COPY packages/esig-core packages/esig-core
COPY packages/esig-gateway packages/esig-gateway

RUN npm run build -w @e-sig/core \
 && npm run build -w @e-sig/assurance-gateway \
 && npm prune --omit=dev

# ---------- runtime ----------
FROM ${NODE_IMAGE} AS runtime

# Chromium + the font set a dossier needs to render deterministically. Without
# fonts, page.pdf() silently produces tofu boxes — a signed, unreadable PDF is
# worse than a failed sign.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium \
      fonts-liberation \
      fonts-dejavu-core \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    ESIG_CHROME_PATH=/usr/bin/chromium \
    ESIG_GATEWAY_STATE_DIR=/var/lib/esig-gateway \
    ESIG_GATEWAY_PORT=8443

WORKDIR /app
COPY --from=builder --chown=node:node /app /app

# State (cert store, PQ key bundles, audit NDJSON) lives on a mounted volume;
# the rest of the filesystem can be read-only.
RUN mkdir -p /var/lib/esig-gateway && chown node:node /var/lib/esig-gateway
VOLUME ["/var/lib/esig-gateway"]

USER node
EXPOSE 8443

# Chromium needs a writable /tmp. With readOnlyRootFilesystem:true, mount an
# emptyDir at /tmp (and at /var/lib/esig-gateway, or a PVC for durable certs).
ENTRYPOINT ["node", "packages/esig-gateway/dist/bin.js"]
