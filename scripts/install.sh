#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
node_root=/ispsupport/node
[[ -f "$node_root/scripts/update.py" && -d "$node_root/.git" ]]
command -v git >/dev/null
command -v python3 >/dev/null
if ! command -v snmpget >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends snmp
fi
install -d -m 750 /etc/ispsupport-node /var/lib/ispsupport-node
install -m 644 "$node_root/systemd/ispsupport-node-update.service" /etc/systemd/system/
install -m 644 "$node_root/systemd/ispsupport-node-update.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ispsupport-node-update.timer
systemctl start ispsupport-node-update.service
