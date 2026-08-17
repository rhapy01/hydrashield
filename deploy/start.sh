#!/bin/sh
set -eu
mkdir -p /data/store /data/cache
TOKEN="${HYDRADB_TOKEN:-local-development-token-32-bytes}"
printf '%s\n' "$TOKEN" > /data/auth-token
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/hydrashield.conf
