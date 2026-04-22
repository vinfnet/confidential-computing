FROM mcr.microsoft.com/aci/skr:2.13 AS skr-source

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

COPY --from=skr-source /bin/skr /usr/local/bin/skr
RUN chmod +x /usr/local/bin/skr && mkdir -p /var/log/supervisor

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 8000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
