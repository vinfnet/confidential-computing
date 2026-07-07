# SecretApp confidential image.
#
#   * Multi-stage build. Stage 1 compiles `get-snp-report` from the upstream
#     microsoft/confidential-sidecar-containers repo at a pinned tag; only the
#     resulting binary is copied into the runtime stage.
#   * Runtime stage starts from a pinned python:3.11-slim (MCR mirror, no Docker
#     Hub rate limit on shared build agents).
#   * Non-root user `secret` (uid 10001). No shell access is reachable at
#     runtime because the CCE policy denies exec_in_container.
#   * The encrypted `sealed-data.enc` bundle is BAKED INTO the image so the image
#     digest covers it too — the SKR release policy (keyed off the CCE policy
#     hash, which is keyed off the image digest) cryptographically binds the
#     sealed secret to the only container that can ever decrypt it.
#
# Built server-side with `az acr build` (no local/agent Docker daemon required),
# so it runs fine on the dockerless confidential ACI build agents.

ARG SIDECAR_TAG=v2.14
ARG BASE_IMAGE=mcr.microsoft.com/mirror/docker/library/python:3.11-slim

# ---------------------------------------------------------------------------
# Stage 1 — build get-snp-report from source.
# ---------------------------------------------------------------------------
FROM mcr.microsoft.com/mirror/docker/library/debian:bookworm-slim AS snp-build
ARG SIDECAR_TAG
RUN apt-get update \
 && apt-get install -y --no-install-recommends git make gcc libc6-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${SIDECAR_TAG} \
        https://github.com/microsoft/confidential-sidecar-containers.git /src
WORKDIR /src/tools/get-snp-report
RUN make bin/get-snp-report \
 && (cd bin && sha256sum get-snp-report > get-snp-report.sha256)

# ---------------------------------------------------------------------------
# Stage 2 — runtime image.
# ---------------------------------------------------------------------------
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    SEALED_DIR=/run/sealed \
    SEALED_BUNDLE=/app/sealed-data.enc \
    GET_SNP_REPORT=/usr/local/bin/get-snp-report

COPY requirements.txt /tmp/requirements.txt
COPY app.py entrypoint.py /app/
COPY templates/ /app/templates/
COPY sealed-data.enc /app/sealed-data.enc
COPY --from=snp-build /src/tools/get-snp-report/bin/get-snp-report        /usr/local/bin/get-snp-report
COPY --from=snp-build /src/tools/get-snp-report/bin/get-snp-report.sha256 /usr/local/bin/get-snp-report.sha256

RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt \
 && groupadd --system --gid 10001 secret \
 && useradd  --system --uid 10001 --gid 10001 --home-dir /app --shell /sbin/nologin secret \
 && chown -R secret:secret /app \
 && chmod 0555 /app /app/templates /usr/local/bin/get-snp-report \
 && chmod 0444 /app/app.py /app/entrypoint.py /app/sealed-data.enc /usr/local/bin/get-snp-report.sha256 \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Verify the SNP report binary checksum at build time so a tampered build cache
# would explode the image.
RUN cd /usr/local/bin && sha256sum -c get-snp-report.sha256

USER secret:secret
WORKDIR /app
EXPOSE 8080

# PID 1 = entrypoint — performs SKR + unseal, then execs the Flask app.
ENTRYPOINT ["python", "/app/entrypoint.py"]
