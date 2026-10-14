# Mandatory node archive rules

These requirements were set by the project owner on 2026-10-14. Preserve them
for every existing and future operator node.

- Every node must provide authenticated FTP configuration storage. Anonymous
  access is forbidden. Use the dedicated FTP-only account `bak`; never give it
  SSH/shell access or access outside its chroot.
- The archive root is `/srv/ispsupport/ftp`, with uploads in `conf/`. Credentials
  are private node configuration in `/etc/ispsupport-node/ftp-credentials.json`
  (root, mode 0600). Never commit credentials or customer configuration files.
- `scripts/install.sh` must install FTP. Reinstallation must preserve archives
  and credentials. The hourly Git updater must not reset configuration or data.
- Network devices archive their configuration to their operator node after
  every commit where the device supports it. Prepare and verify the relevant
  device configuration; do not claim it is enabled unless it was applied.
- The master collects all active nodes daily over its existing SSH key access.
  Master storage: `/var/lib/ispsupport/nodes/<node-name>/ftp/`. Other datasets
  will receive separate subdirectories below the same node directory.
- Preserve copies when files disappear at the source. Preserve the previous
  version before replacing a changed file. No automatic archive deletion.
- Only complete regular files may enter the master archive; verify SHA-256
  before promotion. A failed node must not erase existing copies or prevent
  other nodes from being collected. Record per-node success/failure.
- All administration and collection starts on the ISP Support master. Keep
  customer access, routing, BGP/BRAS, local configuration and existing services
  intact when installing or updating archive components.
