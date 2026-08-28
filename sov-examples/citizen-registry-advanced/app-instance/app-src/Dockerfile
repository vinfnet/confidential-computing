# Citizen Registry Advanced — Dockerfile for Confidential VM Deployment
# Multi-stage build optimized for running on Azure Confidential VM (C-vn2)

FROM python:3.13-slim-bookworm

LABEL maintainer="Citizen Registry Advanced" \
      version="2.0" \
      description="Citizen Registry app with mTLS for Confidential VMs"

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    nginx \
    openssl \
    curl \
    ca-certificates \
    apt-transport-https \
    gnupg \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
       | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
       > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends \
       msodbcsql18 \
       unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

# Create log directories
RUN mkdir -p /var/log/citizen-registry \
    && mkdir -p /var/log/supervisor \
    && mkdir -p /etc/citizen-registry/certs

# Copy application files
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY app.py .
COPY templates/ templates/

# Set proper permissions
RUN chmod 755 /app \
    && chmod 644 /etc/nginx/nginx.conf \
    && chmod 644 /etc/supervisor/conf.d/supervisord.conf \
    && chown -R www-data:www-data /var/log/nginx

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -k --silent --fail -o /dev/null -w "%{http_code}" https://localhost/health || exit 1

EXPOSE 80 443 8000

# Start supervisor (manages nginx + gunicorn)
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
