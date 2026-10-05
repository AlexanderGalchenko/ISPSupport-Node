#!/usr/bin/env python3
"""Bounded LLDP snapshots of explicit inventory devices. Never follows neighbors."""
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from huawei_collect import HuaweiSession, clean_terminal, field

MAX_OUTPUT = 4 * 1024 * 1024
MAX_NEIGHBORS = 1000
MAX_PORTS = 2048
COMMANDS = ('show lldp local-information | display xml | no-more',
            'show lldp neighbors detail | display xml | no-more')


def text(value, limit=255):
    return re.sub(r'[\x00-\x1f\x7f]', ' ', str(value or '')).strip()[:limit]


def mac(value):
    raw = re.sub(r'[:.\-]', '', str(value or '')).lower()
    return ':'.join(raw[i:i+2] for i in range(0, 12, 2)) if re.fullmatch('[0-9a-f]{12}', raw) else text(value)


def addresses(values):
    result = []
    for value in values:
        try:
            address = str(ipaddress.ip_address(value.strip()))
            if address not in result:
                result.append(address)
        except ValueError:
            continue
    return result[:16]


def xml_root(raw):
    if re.search(r'<!DOCTYPE|<!ENTITY', raw, re.I):
        raise ValueError('XML declarations are not permitted')
    match = re.search(r'<rpc-reply\b.*?</rpc-reply>', raw, re.S)
    if not match:
        raise ValueError('Incomplete Junos XML response')
    root = ET.fromstring(match.group())
    for node in root.iter():
        node.tag = node.tag.split('}')[-1]
    if root.find('.//rpc-error') is not None:
        raise ValueError('Junos rejected the LLDP command')
    return root


def value(node, name):
    return text(node.findtext('.//' + name))


def parent(value):
    return None if value in ('', '-', '0', None) else text(value)


def parse_junos(local, neighbors):
    root, remote = xml_root(local), xml_root(neighbors)
    info = root.find('.//lldp-local-info')
    if info is None or remote.find('.//lldp-neighbors-information') is None:
        raise ValueError('Unsupported Junos LLDP response')
    identity = {'chassis_id': mac(value(info, 'lldp-local-chassis-id')),
                'system_name': value(info, 'lldp-local-system-name'),
                'management_addresses': addresses([n.text or '' for n in info.iter('lldp-local-management-address-address')]),
                'ports': []}
    for port in info.iter('lldp-local-interface-info'):
        identity['ports'].append({'name': value(port, 'lldp-local-interface-name'),
                                  'port_id': value(port, 'lldp-local-interface-id'),
                                  'parent': parent(value(port, 'lldp-parent-local-interface-name'))})
    rows = []
    for n in remote.iter('lldp-neighbor-information'):
        rows.append({'local_port': value(n, 'lldp-local-interface'),
                     'local_parent': parent(value(n, 'lldp-local-parent-interface-name')),
                     'chassis_id': mac(value(n, 'lldp-remote-chassis-id')) if 'mac' in value(n, 'lldp-remote-chassis-id-subtype').lower() else value(n, 'lldp-remote-chassis-id'),
                     'chassis_type': value(n, 'lldp-remote-chassis-id-subtype'),
                     'port_id': value(n, 'lldp-remote-port-id'),
                     'port_type': value(n, 'lldp-remote-port-id-subtype'),
                     'port_description': value(n, 'lldp-remote-port-description'),
                     'system_name': value(n, 'lldp-remote-system-name'),
                     'management_addresses': addresses([e.text or '' for e in n.iter('lldp-remote-management-address')])})
    return finish(identity, rows)


def parse_huawei(local, neighbors):
    if not field(local, 'Chassis ID') or not field(local, 'System name'):
        raise ValueError('Huawei local LLDP identity missing')
    identity = {'chassis_id': mac(field(local, 'Chassis ID')), 'system_name': text(field(local, 'System name')),
                'management_addresses': addresses(re.findall(r'Management Address\s*:\s*IP:([^\s]+)', local)), 'ports': []}
    sections = re.split(r'^Interface ([^\n:]+):\s*$', local, flags=re.M)
    for index in range(1, len(sections), 2):
        name, body = sections[index:index + 2]
        identity['ports'].append({'name': text(name), 'port_id': text(field(body, 'Port ID')), 'parent': None})
    rows = []
    blocks = re.split(r'^([^\n]+?) has (\d+) neighbor\(s\):\s*$', neighbors, flags=re.M)
    for index in range(1, len(blocks), 3):
        port, count, body = blocks[index:index + 3]
        entries = re.split(r'^\s*Neighbor index\s*:\s*\d+\s*$', body, flags=re.M)[1:]
        if len(entries) != int(count):
            raise ValueError('Incomplete Huawei LLDP neighbor table')
        for n in entries:
            rows.append({'local_port': text(port), 'local_parent': None,
                         'chassis_id': mac(field(n, 'Chassis ID')) if 'mac' in (field(n, 'Chassis type') or '').lower() else text(field(n, 'Chassis ID')),
                         'chassis_type': text(field(n, 'Chassis type')), 'port_id': text(field(n, 'Port ID')),
                         'port_type': text(field(n, 'Port ID type')), 'port_description': text(field(n, 'Port description')),
                         'system_name': text(field(n, 'System name')),
                         'management_addresses': addresses(re.findall(r'^Management address value\s*:\s*([^\s]+)', n, flags=re.M))})
    if len(blocks) == 1 and not re.search(r'no\s+(?:lldp\s+)?neighbor|neighbor.*(?:number|total)\s*:\s*0', neighbors, re.I):
        total = re.search(r'^Total Neighbors\s*:\s*(\d+)', local, re.M)
        if neighbors.strip() or total is None or total.group(1) != '0':
            raise ValueError('Unrecognized Huawei LLDP table; not an empty snapshot')
    return finish(identity, rows)


def finish(identity, rows):
    if not identity['chassis_id'] or len(rows) > MAX_NEIGHBORS or len(identity['ports']) > MAX_PORTS:
        raise ValueError('LLDP identity or size invalid')
    if any(not r['local_port'] or not r['chassis_id'] or not r['port_id'] for r in rows):
        raise ValueError('LLDP endpoint missing')
    if any(not p['name'] or not p['port_id'] for p in identity['ports']):
        raise ValueError('Local LLDP port identity missing')
    return {'identity': identity, 'neighbors': rows}


def junos_session(host, user, port, known_hosts):
    args = ['ssh', '-F', '/dev/null', '-T', '-p', str(port), '-l', user]
    for option in ['BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'ForwardAgent=no',
                   'PreferredAuthentications=publickey', 'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
                   'StrictHostKeyChecking=accept-new', f'UserKnownHostsFile={known_hosts}',
                   'ConnectTimeout=5', 'ConnectionAttempts=1', 'ServerAliveInterval=3', 'ServerAliveCountMax=1']:
        args.extend(['-o', option])
    args.append(host)
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.stdin.write(('set cli screen-length 0\n' + '\n'.join(COMMANDS) + '\nexit\n').encode())
        proc.stdin.close()
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        deadline, chunks, size = time.monotonic() + 22, [], 0
        try:
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise ValueError('Junos LLDP SSH timeout')
                for key, _ in selector.select(.25):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    if size > MAX_OUTPUT:
                        raise ValueError('LLDP SSH output limit exceeded')
                    chunks.append(chunk)
        finally:
            selector.close()
        proc.wait(timeout=2)
        if proc.returncode:
            raise ValueError('Junos LLDP SSH failed; check access and host key')
        raw = clean_terminal(b''.join(chunks).decode('utf-8', errors='replace'))
        replies = re.findall(r'<rpc-reply\b.*?</rpc-reply>', raw, re.S)
        if len(replies) != 2:
            raise ValueError('LLDP commands rejected or incomplete XML responses')
        return parse_junos(*replies)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3)
        proc.stdout.close()


def collect_one(device, state):
    report = {'id': int(device['id']), 'host': device.get('host'), 'status': 'failed', 'attempted_at': int(time.time())}
    try:
        host = str(ipaddress.ip_address(device['host']))
        user, port = device.get('ssh_username', ''), int(device.get('ssh_port', 22))
        profile = device.get('ssh_profile')
        if profile not in ('junos', 'huawei_vrp'):
            return {**report, 'status': 'unsupported', 'error': 'LLDP SSH profile is not supported'}
        if user == 'root' or not isinstance(user, str) or not re.fullmatch('[a-z_][a-z0-9_-]{0,31}', user) or not 1 <= port <= 65535:
            raise ValueError('Invalid limited SSH user or port')
        known = state / 'device_known_hosts'
        known.touch(mode=0o600, exist_ok=True)
        known.chmod(0o600)
        if profile == 'junos':
            data = junos_session(host, user, port, known)
        else:
            with HuaweiSession(host, user, Path('/root/.ssh/id_rsa'), known, port=port,
                               legacy_rsa=device.get('ssh_legacy_rsa') is True, accept_new_host=True,
                               session_timeout=22, command_timeout=8, connect_timeout=6) as session:
                local = session.command('display lldp local')
                neighbors = session.command('display lldp neighbor')
                data = parse_huawei(local, neighbors)
        return {**report, 'status': 'ok', 'collected_at': int(time.time()), **data}
    except Exception:
        # Never return raw SSH output, credentials, or command-line contents in telemetry.
        return {**report, 'error': 'LLDP collection failed: check SSH access, command permission and complete output'}


def collect_cached(devices, state=Path('/var/lib/ispsupport-node'), force=False):
    if len(devices) > 20 or len({int(d['id']) for d in devices}) != len(devices):
        raise ValueError('At most 20 distinct inventory devices per batch')
    state.mkdir(parents=True, mode=0o750, exist_ok=True)
    folder = state / 'lldp'
    folder.mkdir(mode=0o700, exist_ok=True)
    results, due, now = {}, [], time.time()
    for device in devices:
        ident = int(device['id'])
        if ident <= 0:
            raise ValueError('Invalid device id')
        fingerprint = hashlib.sha256(json.dumps({k: device.get(k) for k in ('id', 'host', 'ssh_username', 'ssh_port', 'ssh_profile', 'ssh_legacy_rsa')}, sort_keys=True).encode()).hexdigest()
        path = folder / (str(ident) + '.json')
        try:
            cached = json.loads(path.read_text())
        except (OSError, ValueError):
            cached = {}
        if cached.get('fingerprint') != fingerprint:
            cached = {}
        previous = cached.get('result')
        if previous:
            results[ident] = previous
        age = now - (previous or {}).get('attempted_at', 0)
        if force or not previous or age >= (600 if previous['status'] == 'ok' else 180) or age < 0:
            due.append((device, path, fingerprint, (previous or {}).get('attempted_at', 0)))
    due.sort(key=lambda item: item[3])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        selected = due[:4]
        for (device, path, fingerprint, _), result in zip(selected, pool.map(lambda item: collect_one(item[0], state), selected)):
            results[int(device['id'])] = result
            with tempfile.NamedTemporaryFile(mode='w', dir=folder, delete=False) as handle:
                json.dump({'fingerprint': fingerprint, 'result': result}, handle)
                temporary = Path(handle.name)
            temporary.replace(path)
    return list(results.values())


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    config = json.loads(Path('/etc/ispsupport-node/node.json').read_text())
    print(json.dumps(collect_cached(config.get('devices', []), force=args.force), ensure_ascii=False))
