# Always-on demo image: HydraDB + API + UI in one machine.
FROM node:22-alpine AS frontend
WORKDIR /ui
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM ghcr.io/hydra-db/hydradb:latest
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv nginx supervisor curl \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv

WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt
COPY backend/hydrashield /app/hydrashield
COPY data /app/data
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY deploy/supervisord.conf /etc/supervisor/conf.d/hydrashield.conf
COPY deploy/start.sh /start.sh
COPY --from=frontend /ui/dist /usr/share/nginx/html
RUN rm -f /etc/nginx/sites-enabled/default \
    && chmod +x /start.sh \
    && mkdir -p /data/store /data/cache

ENV PYTHONPATH=/app \
    HYDRADB_URL=http://127.0.0.1:8443 \
    HYDRADB_TOKEN=local-development-token-32-bytes \
    DATA_DIR=/app/data \
    AUTO_INGEST=true \
    RUST_MIN_STACK=33554432

EXPOSE 8080
CMD ["/start.sh"]
