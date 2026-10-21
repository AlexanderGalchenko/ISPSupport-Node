#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
node_root=${ISPSUPPORT_NODE_ROOT:-/ispsupport/node}
command -v python3 >/dev/null
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io docker-compose-v2
fi
systemctl enable --now docker
install -d -m 750 /etc/ispsupport-node /var/lib/ispsupport-node/zabbix
python3 - <<'PY'
import os, secrets
from pathlib import Path
p=Path('/etc/ispsupport-node/zabbix.env')
if not p.exists():
    with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:
        f.write('POSTGRES_USER=zabbix\nPOSTGRES_DB=zabbix\nPOSTGRES_PASSWORD='+secrets.token_hex(32)+'\n')
PY
compose=(docker compose --env-file /etc/ispsupport-node/zabbix.env -f "$node_root/zabbix/compose.yaml")
"${compose[@]}" pull db server
web_image=$("${compose[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["web"]["image"])')
if [[ "$web_image" == ispsupport-zabbix-web:security-20261021-8.5.12 ]]; then
    docker build -t "$web_image" -f "$node_root/zabbix/Dockerfile.web" "$node_root/zabbix"
else
    docker pull "$web_image"
fi
docker compose --env-file /etc/ispsupport-node/zabbix.env -f "$node_root/zabbix/compose.yaml" up -d
python3 "$node_root/scripts/bootstrap_zabbix.py"
bash "$node_root/scripts/install-zabbix-sync.sh"
