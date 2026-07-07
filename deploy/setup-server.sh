#!/usr/bin/env bash
# One-time (idempotent) setup for the Evan-pi API on the server.
# Run as root ON THE SERVER after the repo has been pulled to /srv/Evan-pi:
#
#   ssh root@208.87.130.181 'bash /srv/Evan-pi/deploy/setup-server.sh'
#
# It installs the systemd service and its data dir. It does NOT edit the nginx
# site config automatically — add the block from deploy/nginx-api-location.conf
# into the HTTPS server{} for evan.leckliter.net, then `nginx -t && systemctl
# reload nginx` (the deploy script already reloads nginx once that's in place).
set -euo pipefail

DATA_DIR=/var/lib/evan-api
UNIT_SRC=/srv/Evan-pi/deploy/evan-api.service
UNIT_DST=/etc/systemd/system/evan-api.service

echo "==> Creating data dir $DATA_DIR (owned by www-data)"
mkdir -p "$DATA_DIR"
chown www-data:www-data "$DATA_DIR"
chmod 750 "$DATA_DIR"

echo "==> Installing systemd unit"
cp "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable --now evan-api

echo "==> Service status:"
systemctl --no-pager --lines=0 status evan-api || true

echo "==> Health check:"
sleep 1
curl -fsS http://127.0.0.1:8787/api/health && echo

cat <<'NOTE'

Done. Remaining manual step (first time only):
  1. Edit /etc/nginx/sites-available/evan.leckliter.net
  2. Paste the location /api/ { ... } block from
     /srv/Evan-pi/deploy/nginx-api-location.conf into the HTTPS server{} block
  3. nginx -t && systemctl reload nginx

After that, the deploy script keeps things current; restart the API on code
changes with:  systemctl restart evan-api
NOTE
