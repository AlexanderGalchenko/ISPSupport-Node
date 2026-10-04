#!/usr/bin/env python3
"""Bounded, on-demand Huawei VRP operational inventory. No configuration writes."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

MAX_OUTPUT = 4 * 1024 * 1024
MAX_SESSION = 16 * 1024 * 1024
COMMANDS = {
    'screen-length 0 temporary', 'display version', 'display vsi verbose',
    'display mpls ldp session', 'display eth-trunk', 'display mac-address',
}
VSI_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z')
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
USER_PROMPT = re.compile(r'(?:^|\n)<([A-Za-z0-9_.:-]{1,100})>[ \t]*\Z')
CLI_ERROR = re.compile(r'(?im)^\s*(?:Error:|%\s*(?:Error|Fail)|Permission denied|Failure:)')


class CollectionError(RuntimeError):
    pass


class CommandError(CollectionError):
    pass


def clean_terminal(text):
    text = ANSI.sub('', text).replace('\r', '')
    # Terminal redraws may erase characters; do not retain erased text.
    while '\b' in text:
        updated = re.sub(r'[^\n\b]\x08', '', text)
        if updated == text:
            return text.replace('\b', '')
        text = updated
    return text


def permitted(command):
    return command in COMMANDS or (
        command.startswith('display mac-address vsi ')
        and VSI_NAME.fullmatch(command[len('display mac-address vsi '):]) is not None
    )


def ssh_arguments(host, user, key, known_hosts, port=22, legacy_rsa=False, accept_new_host=False):
    host = str(ipaddress.ip_address(host))
    if user == 'root' or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise ValueError('A limited equipment username is required')
    if not 1 <= port <= 65535:
        raise ValueError('Invalid SSH port')
    args = ['-F', '/dev/null', '-tt', '-i', str(key), '-p', str(port)]
    options = [
        'BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none',
        'PreferredAuthentications=publickey', 'PasswordAuthentication=no',
        'KbdInteractiveAuthentication=no', 'ForwardAgent=no',
        'StrictHostKeyChecking=accept-new' if accept_new_host else 'StrictHostKeyChecking=yes', f'UserKnownHostsFile={known_hosts}',
        'ConnectTimeout=6', 'ConnectionAttempts=1',
        'ServerAliveInterval=3', 'ServerAliveCountMax=2', 'LogLevel=ERROR',
    ]
    if legacy_rsa:
        # User authentication compatibility only; host-key algorithms are unchanged.
        options.append('PubkeyAcceptedAlgorithms=+ssh-rsa')
    for option in options:
        args.extend(['-o', option])
    return args + ['-l', user, host]


class HuaweiSession:
    def __init__(self, host, user, key, known_hosts, port=22, legacy_rsa=False,
                 session_timeout=120, command_timeout=30, connect_timeout=15, accept_new_host=False):
        try:
            import pexpect
        except ImportError:
            raise CollectionError('Install the Ubuntu/Debian python3-pexpect package') from None
        self.pexpect = pexpect
        self.deadline = time.monotonic() + session_timeout
        self.command_timeout = command_timeout
        self.total = 0
        self.hostname = None
        args = ssh_arguments(host, user, key, known_hosts, port, legacy_rsa, accept_new_host)
        self.child = pexpect.spawn('ssh', args, encoding='utf-8', codec_errors='replace',
                                   echo=False, dimensions=(80, 240), maxread=65536)
        try:
            _, self.hostname = self._read_prompt(connect_timeout)
            self.command('screen-length 0 temporary')
        except Exception:
            self.close()
            raise

    def _read_prompt(self, timeout):
        deadline = min(self.deadline, time.monotonic() + timeout)
        parts, size = [], 0
        while time.monotonic() < deadline:
            try:
                chunk = self.child.read_nonblocking(65536, timeout=min(1, max(.01, deadline - time.monotonic())))
            except self.pexpect.TIMEOUT:
                continue
            except self.pexpect.EOF:
                tail = ''.join(parts[-3:]).lower()
                if 'host key verification failed' in tail or 'host identification has changed' in tail:
                    raise CollectionError('SSH host key verification failed') from None
                if 'permission denied' in tail:
                    raise CollectionError('SSH public key rejected') from None
                if 'no mutual signature' in tail or 'no matching' in tail:
                    raise CollectionError('SSH algorithms incompatible') from None
                raise CollectionError('SSH closed before a complete CLI response; verify key, host key and permissions') from None
            size += len(chunk.encode('utf-8'))
            self.total += len(chunk.encode('utf-8'))
            if size > MAX_OUTPUT or self.total > MAX_SESSION:
                raise CollectionError('Output limit exceeded; retry with --vsi to narrow MAC collection')
            parts.append(chunk)
            # Only inspect the tail until the actual prompt has arrived.
            tail = clean_terminal(''.join(parts[-3:]))
            match = USER_PROMPT.search(tail)
            if match and (self.hostname is None or match.group(1) == self.hostname):
                text = clean_terminal(''.join(parts))
                final = USER_PROMPT.search(text)
                return text[:final.start()].strip('\n'), match.group(1)
        raise CollectionError('SSH/CLI deadline exceeded; incomplete data discarded')

    def command(self, command):
        if not permitted(command):
            raise ValueError('Command is outside the read-only collection allowlist')
        self.child.sendline(command)
        text, _ = self._read_prompt(self.command_timeout)
        lines = text.splitlines()
        if lines and lines[0].strip() == command:
            lines.pop(0)
        text = '\n'.join(lines).strip()
        if CLI_ERROR.search(text):
            raise CommandError('Command rejected by the device (syntax or access level)')
        if re.search(r'-{2,}\s*More\s*-{2,}', text, re.I):
            raise CollectionError('Incomplete paginated response')
        return text

    def close(self):
        child = getattr(self, 'child', None)
        if child is not None:
            child.close(force=True)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def field(text, label):
    match = re.search(r'^[ \t]*' + re.escape(label) + r'[ \t]*:[ \t]*([^\n]*)', text, re.M)
    return match.group(1).strip() if match else None


def integer(value):
    return int(value) if value is not None and value.isdecimal() else None


def require_output(text):
    if not text.strip() or CLI_ERROR.search(text):
        raise ValueError('Empty or rejected response')


def parse_version(text):
    require_output(text)
    version = re.search(r'\bV\d{3}R\d{3}C\d{2}(?:SPC\d+)?\b', text)
    model = re.search(r'^HUAWEI\s+(\S+)\s+.*?uptime is (.+)$', text, re.M)
    if not version or not model:
        raise ValueError('Unrecognized VRP version response')
    return {'model': model.group(1), 'software': version.group(0), 'uptime': model.group(2).strip()}


def parse_vsi(text):
    require_output(text)
    blocks = re.split(r'^\s*\*{3}VSI Name\s*:\s*', text, flags=re.M)[1:]
    if not blocks and not re.search(r'no\s+vsi|VSI.*(?:number|total).*\b0\b', text, re.I):
        raise ValueError('Unrecognized VSI response')
    result = []
    for block in blocks:
        name, _, body = block.partition('\n')
        if not field(body, 'VSI State'):
            raise ValueError('VSI state missing')
        peers = {}
        for part in re.split(r'^\s*\*Peer Router ID\s*:\s*', body, flags=re.M)[1:]:
            peer_ip, _, details = part.partition('\n')
            details = re.split(r'^\s*(?:Interface Name|\*\*PW Information)', details, maxsplit=1, flags=re.M)[0]
            peer_ip = str(ipaddress.ip_address(peer_ip.strip()))
            peers[peer_ip] = {'peer_ip': peer_ip, 'session_state': field(details, 'Session'),
                              'vc_id': integer(field(details, 'Negotiation-vc-id')),
                              'local_label': integer(field(details, 'VC Label')), 'pw_state': None}
        for part in re.split(r'^\s*\*Peer Ip Address\s*:\s*', body, flags=re.M)[1:]:
            peer_ip, _, details = part.partition('\n')
            peer_ip = str(ipaddress.ip_address(peer_ip.strip()))
            peer = peers.setdefault(peer_ip, {'peer_ip': peer_ip, 'session_state': None})
            peer.update(pw_state=field(details, 'PW State'),
                        local_label=integer(field(details, 'Local VC Label')),
                        remote_label=integer(field(details, 'Remote VC Label')),
                        out_interface=field(details, 'OutInterface'))
        interfaces = []
        for part in re.split(r'^\s*Interface Name\s*:\s*', body, flags=re.M)[1:]:
            interface, _, details = part.partition('\n')
            interfaces.append({'name': interface.strip(), 'state': field(details, 'State')})
        result.append({'name': name.strip(), 'id': integer(field(body, 'VSI ID')),
                       'state': field(body, 'VSI State'), 'signaling': field(body, 'PW Signaling'),
                       'mtu': integer(field(body, 'MTU')), 'interfaces': interfaces,
                       'peers': list(peers.values())})
    return result


def parse_trunks(text):
    require_output(text)
    sections = re.split(r"^(Eth-Trunk\d+)'s state information is:\s*$", text, flags=re.M)
    if len(sections) == 1:
        if re.search(r'no.*eth-trunk|eth-trunk.*not exist', text, re.I):
            return []
        raise ValueError('Unrecognized Eth-Trunk response')
    trunks = []
    for pos in range(1, len(sections), 2):
        name, block = sections[pos:pos + 2]
        local = block.split('Partner:', 1)[0]
        status = re.search(r'Operate status:\s*(\S+)', local)
        count = re.search(r'Number Of Up Port In Trunk:\s*(\d+)', local)
        mode = re.search(r'WorkingMode:\s*(\S+)', local)
        if not status or not count:
            raise ValueError('Eth-Trunk status or member count missing')
        members = []
        for match in re.finditer(r'^\s*(\S+(?:/\d+){2})\s+(Selected|Unselect|Up|Down)\s+(\S+)', local, re.M | re.I):
            members.append({'name': match.group(1), 'state': match.group(2), 'port_type': match.group(3)})
        if int(count.group(1)) > len(members):
            raise ValueError('Eth-Trunk member table incomplete')
        trunks.append({'name': name, 'state': status.group(1),
                       'up_members': int(count.group(1)), 'mode': mode.group(1) if mode else None,
                       'members': members})
    return trunks


def parse_ldp(text):
    require_output(text)
    rows = []
    for match in re.finditer(r'^\s*(\*?)(\d+(?:\.\d+){3}):(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)/(\d+)\s*$', text, re.M):
        rows.append({'peer_ip': str(ipaddress.ip_address(match.group(2))),
                     'label_space': int(match.group(3)), 'state': match.group(4),
                     'role': match.group(6), 'age': match.group(7),
                     'deleting': bool(match.group(1))})
    total = re.search(r'TOTAL:\s*(\d+)\s+session', text, re.I)
    if total is None or int(total.group(1)) != len(rows):
        raise ValueError('LDP session table incomplete or unsupported')
    return rows


def parse_macs(text):
    require_output(text)
    rows = []
    for match in re.finditer(r'^[ \t]*([0-9a-f]{4}(?:-[0-9a-f]{4}){2})[ \t]+((?:[0-9]+|-)/[^/\s]+/(?:[0-9]+|-))[ \t]*(\S+)[ \t]+(\S+)[ \t]*$', text, re.M | re.I):
        mac, domain, learned, kind = match.groups()
        digits = mac.replace('-', '').lower()
        parts = domain.split('/')
        rows.append({'mac': ':'.join(digits[i:i + 2] for i in range(0, 12, 2)),
                     'domain': domain, 'vlan': integer(parts[0]),
                     'vsi': parts[1] if len(parts) == 3 and parts[1] != '-' else None,
                     'bridge_domain': integer(parts[2]) if len(parts) == 3 else None,
                     'learned_from': learned, 'type': kind.lower()})
    total = re.search(r'Total items displayed\s*=\s*(\d+)', text, re.I)
    if total is None:
        if not rows and re.search(r'no\s+mac.address|MAC address.*not exist', text, re.I):
            return []
        raise ValueError('MAC table total missing')
    if int(total.group(1)) != len(rows):
        raise ValueError('MAC table incomplete or unsupported; no partial count returned')
    return rows


def findings(report):
    result = []
    ldp = report.get('ldp')
    operational = {p['peer_ip'] for p in ldp or [] if p['state'].lower() == 'operational' and not p['deleting']}
    for vsi in report.get('vsi') or []:
        if vsi['state'].lower() != 'up':
            kind = 'vsi_unconfigured' if vsi['signaling'] in (None, '', '--') else 'vsi_down'
            result.append({'kind': kind, 'vsi': vsi['name'], 'state': vsi['state']})
        for peer in vsi['peers']:
            state = peer.get('pw_state') or peer.get('session_state')
            if state and state.lower() != 'up':
                item = {'kind': 'pw_down', 'vsi': vsi['name'], 'peer_ip': peer['peer_ip'], 'state': state}
                if ldp is not None:
                    item['ldp_operational'] = peer['peer_ip'] in operational
                result.append(item)
        for interface in vsi['interfaces']:
            if interface['state'] and interface['state'].lower() != 'up':
                result.append({'kind': 'attachment_down', 'vsi': vsi['name'], 'interface': interface['name'], 'state': interface['state']})
    for trunk in report.get('trunks') or []:
        if trunk['state'].lower() != 'up':
            result.append({'kind': 'trunk_down' if trunk['members'] else 'trunk_without_members', 'trunk': trunk['name']})
        elif trunk['up_members'] < len(trunk['members']):
            result.append({'kind': 'trunk_inactive_members', 'trunk': trunk['name'],
                           'up': trunk['up_members'], 'total': len(trunk['members'])})
    return result


def build_report(outputs, host, hostname, legacy_rsa=False, vsi=None):
    report = {'schema_version': 1, 'collected_at': datetime.now(timezone.utc).isoformat(),
              'device': {'host': host, 'hostname': hostname},
              'ssh': {'authentication': 'publickey', 'legacy_rsa_enabled': legacy_rsa},
              'mac_scope': {'vsi': vsi}, 'collection_errors': []}
    mac_command = 'display mac-address' + (f' vsi {vsi}' if vsi else '')
    sections = [('version', 'display version', parse_version), ('vsi', 'display vsi verbose', parse_vsi),
                ('ldp', 'display mpls ldp session', parse_ldp), ('trunks', 'display eth-trunk', parse_trunks),
                ('macs', mac_command, parse_macs)]
    for section, command, parser in sections:
        report[section] = None
        try:
            raw = outputs.get(command)
            if raw is None:
                raise ValueError('Command unavailable or rejected')
            report[section] = parser(raw)
        except ValueError as exc:
            report['collection_errors'].append({'section': section, 'message': str(exc)})
    report['complete'] = not report['collection_errors']
    report['findings'] = findings(report)
    return report


def private_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def summary(report):
    lines = [f"{report['device']['hostname']} ({report['device']['host']})", f"Снято: {report['collected_at']}"]
    if report['version']:
        lines.append(f"{report['version']['model']} / {report['version']['software']}")
    for name, title, up in [('vsi', 'VSI', 'up'), ('ldp', 'LDP', 'operational'), ('trunks', 'Eth-Trunk', 'up')]:
        rows = report[name]
        if rows is not None:
            count = sum(row['state'].lower() == up for row in rows)
            lines.append(f'{title}: {len(rows)}, работают: {count}')
    if report['macs'] is not None:
        lines.append(f"Записей MAC: {len(report['macs'])} (это не число абонентов)")
    for error in report['collection_errors']:
        lines.append(f"НЕТ ДАННЫХ {error['section']}: {error['message']}")
    for item in report['findings']:
        lines.append('Наблюдение: ' + json.dumps(item, ensure_ascii=False))
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, type=lambda value: str(ipaddress.ip_address(value)))
    parser.add_argument('--user', default='ispsupport')
    parser.add_argument('--key', default='/root/.ssh/id_rsa')
    parser.add_argument('--known-hosts', default='/var/lib/ispsupport-node/device_known_hosts')
    parser.add_argument('--port', default=22, type=int)
    parser.add_argument('--legacy-rsa', action='store_true', help='Permit ssh-rsa user signatures for this connection only')
    parser.add_argument('--vsi', help='Collect MAC entries for one VSI; service/trunk status remains device-wide')
    parser.add_argument('--output', type=Path, help='Store a structured report atomically with mode 0600')
    parser.add_argument('--json', action='store_true', help='Print the structured report instead of the summary')
    args = parser.parse_args(argv)
    if args.vsi and not VSI_NAME.fullmatch(args.vsi):
        parser.error('Unsupported VSI name')
    try:
        commands = ['display version', 'display vsi verbose', 'display mpls ldp session', 'display eth-trunk',
                    'display mac-address' + (f' vsi {args.vsi}' if args.vsi else '')]
        outputs = {}
        with HuaweiSession(args.host, args.user, args.key, args.known_hosts, args.port, args.legacy_rsa) as session:
            hostname = session.hostname
            for command in commands:
                try:
                    outputs[command] = session.command(command)
                except CommandError:
                    outputs[command] = None
        report = build_report(outputs, args.host, hostname, args.legacy_rsa, args.vsi)
        if args.output:
            private_json(args.output, report)
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else summary(report))
        return 0 if report['complete'] else 2
    except (CollectionError, ValueError, OSError) as exc:
        print(f'Collection failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
