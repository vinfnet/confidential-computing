FROM mcr.microsoft.com/aci/skr:2.13 AS skr-source

FROM python:3.13-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    nginx \
    openssl \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN mkdir -p /etc/nginx/ssl \
    && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout /etc/nginx/ssl/server.key \
       -out /etc/nginx/ssl/server.crt \
       -subj "/C=US/ST=WA/L=Redmond/O=SOV Demo/CN=*.azurecontainer.io" \
       -addext "subjectAltName=DNS:*.azurecontainer.io,DNS:localhost" \
    && chmod 600 /etc/nginx/ssl/server.key \
    && chmod 644 /etc/nginx/ssl/server.crt

COPY --from=skr-source /bin/skr /usr/local/bin/skr
RUN chmod +x /usr/local/bin/skr

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY app.py /app/app.py
COPY templates/ /app/templates/
COPY seed-data.sql /app/seed-data.sql

RUN mkdir -p /var/log/supervisor /var/log/nginx /var/run \
    && chown -R appuser:appuser /app /var/log/supervisor /var/run \
    && chmod -R 755 /app

EXPOSE 80 443

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
