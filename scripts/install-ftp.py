#!/usr/bin/env python3
"""Install the mandatory private node FTP archive without exposing passwords."""
import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import tempfile

SETTINGS = Path('/etc/ispsupport-node')
ROOT = Path('/srv/ispsupport/ftp')
UNIT = 'ispsupport-ftp.service'
MARKER = SETTINGS / 'ftp-managed.json'

CONFIG = '''listen=YES
listen_ipv6=NO
background=NO
listen_port=21
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=077
file_open_mode=0600
chroot_local_user=YES
allow_writeable_chroot=NO
local_root=/srv/ispsupport/ftp
userlist_enable=YES
userlist_deny=NO
userlist_file=/etc/ispsupport-node/ftp-users
pam_service_name=ispsupport-ftp
secure_chroot_dir=/run/vsftpd/empty
pasv_enable=YES
pasv_min_port=50000
pasv_max_port=50049
port_enable=YES
connect_from_port_20=YES
pasv_promiscuous=NO
port_promiscuous=NO
ssl_enable=NO
hide_ids=YES
max_clients=20
max_per_ip=5
idle_session_timeout=300
data_connection_timeout=120
accept_timeout=60
connect_timeout=60
delay_failed_login=3
xferlog_enable=YES
xferlog_std_format=NO
vsftpd_log_file=/var/log/ispsupport-ftp.log
log_ftp_protocol=NO
ls_recurse_enable=NO
chmod_enable=NO
lock_upload_files=YES
'''

SERVICE = '''[Unit]
Description=ISP Support authenticated FTP configuration archive
After=network.target

[Service]
Type=simple
ExecStartPre=/usr/bin/install -d -m 755 -o root -g root /run/vsftpd/empty
ExecStart=/usr/sbin/vsftpd /etc/ispsupport-node/vsftpd.conf
Restart=on-failure
RestartSec=5
UMask=0077
PrivateTmp=true

[Install]
WantedBy=multi-user.target
'''

PAM = '''# Only the dedicated node FTP account may authenticate.
auth required pam_listfile.so item=user sense=allow file=/etc/ispsupport-node/ftp-users onerr=fail
@include common-auth
@include common-account
@include common-session
'''


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def write(path, content, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('Refusing a symlink: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    changed = not path.exists() or path.read_text() != content
    if changed:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as handle:
            handle.write(content)
            name = handle.name
        os.chmod(name, mode)
        os.replace(name, path)
    os.chmod(path, mode)
    os.chown(path, 0, 0)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--password-stdin', action='store_true', help='Set bak password from stdin; never from argv')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run as root')
    os.umask(0o077)
    supplied = sys.stdin.read().rstrip('\r\n') if args.password_stdin else None
    if supplied is not None and (not supplied or any(ord(c) < 32 or ord(c) == 127 for c in supplied)):
        raise RuntimeError('A nonempty single-line password is required')
    managed = MARKER.exists()
    try:
        account = pwd.getpwnam('bak')
    except KeyError:
        account = None
    if account and not managed:
        raise RuntimeError('An unmanaged bak account already exists; preserve it and review before installation')
    if not managed and (ROOT.exists() or Path('/etc/vsftpd.conf').exists()):
        raise RuntimeError('An unmanaged FTP installation or archive directory exists; preserve it and review')
    sshd = Path('/etc/ssh/sshd_config')
    if not any(line.strip() == 'Include /etc/ssh/sshd_config.d/*.conf' for line in sshd.read_text().splitlines()):
        raise RuntimeError('Expected sshd_config.d Include is absent; cannot enforce FTP-only authentication safely')
    SETTINGS.mkdir(mode=0o750, parents=True, exist_ok=True)
    write(MARKER, json.dumps({'schema': 1, 'root': str(ROOT), 'user': 'bak'}) + '\n')
    # The distribution service must never start with its generic configuration.
    run(['systemctl', 'mask', 'vsftpd.service'])
    missing = [package for binary, package in [('vsftpd', 'vsftpd'), ('rsync', 'rsync')] if not shutil.which(binary)]
    if missing:
        run(['apt-get', 'update'])
        run(['apt-get', 'install', '-y', '--no-install-recommends', *missing], env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    credentials = SETTINGS / 'ftp-credentials.json'
    previous = json.loads(credentials.read_text()) if credentials.exists() else {}
    if credentials.exists() and (not isinstance(previous, dict) or previous.get('username') != 'bak' or not isinstance(previous.get('password'), str) or not previous['password']):
        raise RuntimeError('Saved FTP credentials are invalid; refusing to reset them implicitly')
    password = supplied if supplied is not None else previous.get('password') or secrets.token_urlsafe(30)
    if any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise RuntimeError('Invalid saved FTP password')
    created_account = account is None
    if created_account:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', str(ROOT), '--shell', '/usr/sbin/nologin', 'bak'])
        account = pwd.getpwnam('bak')
    if account.pw_dir != str(ROOT) or account.pw_shell != '/usr/sbin/nologin':
        raise RuntimeError('The managed bak account was changed; refusing to overwrite its settings')
    if ROOT.parent.is_symlink():
        raise RuntimeError('FTP parent directory must not be a symlink')
    ROOT.parent.mkdir(mode=0o711, parents=True, exist_ok=True)
    os.chown(ROOT.parent, 0, 0)
    ROOT.parent.chmod(0o711)
    for path in [ROOT, ROOT / 'conf']:
        if path.is_symlink():
            raise RuntimeError('Archive root must not contain symlinks')
        path.mkdir(parents=True, exist_ok=True)
    os.chown(ROOT, 0, 0)
    ROOT.chmod(0o755)
    os.chown(ROOT / 'conf', account.pw_uid, account.pw_gid)
    (ROOT / 'conf').chmod(0o700)
    # nologin alone does not block SSH forwarding. Deny the account at SSH authentication.
    deny = Path('/etc/ssh/sshd_config.d/90-ispsupport-ftp.conf')
    before = deny.read_bytes() if deny.exists() else None
    ssh_changed = write(deny, '# Managed by ISP Support: this account is FTP-only.\nDenyUsers bak\n', 0o644)
    try:
        run(['/usr/sbin/sshd', '-t'])
    except Exception:
        if before is None:
            deny.unlink()
        else:
            deny.write_bytes(before)
        raise
    if ssh_changed:
        run(['systemctl', 'reload', 'ssh.service'])
    if not previous or supplied is not None or created_account:
        run(['chpasswd'], input='bak:' + password + '\n', text=True, stdout=subprocess.DEVNULL)
        write(credentials, json.dumps({'username': 'bak', 'password': password}, ensure_ascii=False) + '\n')
    changed = write(SETTINGS / 'vsftpd.conf', CONFIG)
    changed = write(SETTINGS / 'ftp-users', 'bak\n') or changed
    changed = write('/etc/pam.d/ispsupport-ftp', PAM, 0o644) or changed
    changed = write('/etc/systemd/system/' + UNIT, SERVICE, 0o644) or changed
    write('/etc/logrotate.d/ispsupport-ftp', '/var/log/ispsupport-ftp.log {\n daily\n rotate 14\n compress\n missingok\n notifempty\n copytruncate\n create 0600 root root\n}\n', 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', UNIT])
    active = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT]).returncode == 0
    if changed or not active:
        run(['systemctl', 'restart' if active else 'start', UNIT])
    run(['systemctl', 'is-active', '--quiet', UNIT])
    print(json.dumps({'status': 'ready', 'user': 'bak', 'root': str(ROOT), 'upload_directory': '/conf', 'anonymous': False, 'password_changed': supplied is not None or not previous or created_account}))


if __name__ == '__main__':
    main()
