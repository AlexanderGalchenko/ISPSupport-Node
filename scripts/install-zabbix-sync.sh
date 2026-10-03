#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
node_root=${ISPSUPPORT_NODE_ROOT:-/ispsupport/node}
[[ "$node_root" == /ispsupport/node ]] || { echo 'Unsupported node root' >&2; exit 1; }
[[ -f /etc/ispsupport-node/zabbix-api.json && -f "$node_root/scripts/zabbix_sync.py" ]]
install -d -m 750 /var/lib/ispsupport-node
install -m 644 "$node_root/systemd/ispsupport-zabbix-sync.service" /etc/systemd/system/
install -m 644 "$node_root/systemd/ispsupport-zabbix-sync.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ispsupport-zabbix-sync.timer
systemctl start ispsupport-zabbix-sync.service
