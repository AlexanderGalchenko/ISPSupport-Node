#!/usr/bin/env bash
# Install explicitly; the Git update timer never installs or restarts services.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
repo=/ispsupport/node
[[ -f "$repo/scripts/pppoe.py" ]] || { echo "Missing $repo/scripts/pppoe.py" >&2; exit 1; }
missing=()
for pair in python3:python3 ip:iproute2 pppd:ppp ping:iputils-ping curl:curl dig:dnsutils sysctl:procps modprobe:kmod; do
    command -v "${pair%%:*}" >/dev/null || missing+=("${pair#*:}")
done
if ((${#missing[@]})); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi
modprobe pppoe
install -d -m 700 /etc/ispsupport-node/pppoe /var/lib/ispsupport-node/pppoe
backup="/var/lib/ispsupport-node/pppoe/install-backup-$(date -u +%Y%m%dT%H%M%S)-$$"
install -d -m 700 "$backup"
for filename in ispsupport-pppoe@.service ispsupport-pppoe-probe@.service ispsupport-pppoe-probe@.timer; do
    destination="/etc/systemd/system/$filename"
    if [[ -e "$destination" ]]; then cp -a "$destination" "$backup/$filename"; fi
    install -m 644 "$repo/systemd/$filename" "$destination"
done
if [[ -e /usr/local/sbin/ispsupport-pppoe ]]; then
    cp -a /usr/local/sbin/ispsupport-pppoe "$backup/ispsupport-pppoe"
fi
cat > /usr/local/sbin/ispsupport-pppoe <<'COMMAND'
#!/bin/sh
exec /usr/bin/python3 /ispsupport/node/scripts/pppoe.py "$@"
COMMAND
chmod 755 /usr/local/sbin/ispsupport-pppoe
if [[ -e /etc/modules-load.d/ispsupport-pppoe.conf ]]; then
    cp -a /etc/modules-load.d/ispsupport-pppoe.conf "$backup/ispsupport-pppoe.conf"
fi
printf 'pppoe\n' > /etc/modules-load.d/ispsupport-pppoe.conf
chmod 644 /etc/modules-load.d/ispsupport-pppoe.conf
systemctl daemon-reload
echo "Installed; no sessions started or restarted. Previous files: $backup"
