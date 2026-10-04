"""Bounded interface inventory; no subscriber counters or full configuration leave the node."""
import ipaddress
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

IF_NAME = '.1.3.6.1.2.1.31.1.1.1.1'
IF_TYPE = '.1.3.6.1.2.1.2.2.1.3'
IF_SPEED = '.1.3.6.1.2.1.31.1.1.1.15'
IF_ALIAS = '.1.3.6.1.2.1.31.1.1.1.18'
PHYSICAL = re.compile(r'^(?:ge|xe|et|fe)-\d+/\d+/\d+(?::\d+)?$')
LAG = re.compile(r'^ae\d+$')
FORBIDDEN = re.compile(r'^(?:demux|pp\d|pppoe|ippp|dyn|vtep|dsc|jsrv|pfe|pfh|lc-|lsi|mtun|tap)', re.I)
SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_./:\-]{0,79}$')
MAX_INTERFACES = 1000


def bounded_command(args, timeout, env=None):
    def bound_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        try:
            reply = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                                   timeout=timeout, env=env, preexec_fn=bound_output)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError('Inventory command unavailable or timed out') from None
        if reply.returncode:
            raise RuntimeError('Inventory command failed or exceeded output limit')
        output.seek(0)
        return output.read(4 * 1024 * 1024).decode('utf-8', errors='replace')


class Snmp:
    def __init__(self, device):
        self.deadline = time.monotonic() + 60
        self.host = str(ipaddress.ip_address(device['host']))
        self.port = int(device.get('snmp_port', 161))
        self.community = device.get('snmp_community')
        if not 1 <= self.port <= 65535 or not self.community or any(ord(c) < 32 or ord(c) == 127 for c in self.community):
            raise ValueError('Invalid SNMP configuration')

    def query(self, oids, walk=False):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('Interface discovery time budget exceeded')
        with tempfile.TemporaryDirectory(prefix='isp-discovery-') as directory:
            value = self.community.replace('\\', '\\\\').replace('"', '\\"')
            path = Path(directory) / 'snmp.conf'
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
                handle.write('defVersion 2c\ndefCommunity "' + value + '"\n')
            address = f'udp6:[{self.host}]:{self.port}' if ':' in self.host else f'udp:{self.host}:{self.port}'
            args = ['snmpbulkwalk' if walk else 'snmpget', '-v', '2c', '-t', '1', '-r', '1', '-OnQet']
            if walk:
                args += ['-Cr25']
            raw = bounded_command(args + [address] + oids, min(remaining, 25 if walk else 5), {**os.environ, 'SNMPCONFPATH': directory, 'MIBS': ''})
            values = {}
            for line in raw.splitlines():
                match = re.match(r'^(\.\d+(?:\.\d+)*)\s*=\s*(.*)$', line)
                if match:
                    values[match[1]] = match[2].strip().strip('"')
            return values


def interface_configuration(xml):
    start = xml.find('<')
    if start < 0 or '<!DOCTYPE' in xml or '<!ENTITY' in xml:
        raise ValueError('Invalid configuration XML')
    end = xml.find('</rpc-reply>')
    if end >= 0:
        xml = xml[:end + len('</rpc-reply>')]
    root = ET.fromstring(xml[start:])
    for element in root.iter():
        element.tag = element.tag.split('}')[-1]
    configurations = list(root.iter('configuration'))
    if not configurations:
        raise ValueError('Configuration XML not returned; verify read-only permissions')
    units = set()
    aggregates = {}
    for config in configurations:
        for interface in config.findall('./interfaces/interface'):
            name = (interface.findtext('name') or '').strip()
            if not SAFE_NAME.fullmatch(name) or FORBIDDEN.match(name) or 'inactive' in interface.attrib:
                continue
            if PHYSICAL.fullmatch(name):
                aggregates[name] = None
                for options in interface:
                    if options.tag not in ('ether-options', 'gigether-options', 'fastether-options') or 'inactive' in options.attrib:
                        continue
                    for setting in options.findall('ieee-802.3ad'):
                        bundle = setting.find('bundle')
                        if 'inactive' not in setting.attrib and bundle is not None and 'inactive' not in bundle.attrib:
                            value = (bundle.text or '').strip()
                            if LAG.fullmatch(value):
                                aggregates[name] = value
            for unit in interface.findall('unit'):
                number = (unit.findtext('name') or '').strip()
                if number.isdecimal() and 'inactive' not in unit.attrib:
                    units.add(name + '.' + number)
    return {'units': units, 'aggregates': aggregates}


def static_units(xml):
    return interface_configuration(xml)['units']


def read_interface_configuration(device):
    username = device.get('ssh_username') or ''
    if username == 'root' or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', username):
        raise ValueError('Limited SSH username required for static units')
    host = str(ipaddress.ip_address(device['host']))
    port = int(device.get('ssh_port', 22))
    if not 1 <= port <= 65535:
        raise ValueError('Invalid SSH port')
    state = Path('/var/lib/ispsupport-node')
    state.mkdir(mode=0o750, parents=True, exist_ok=True)
    known = state / 'device_known_hosts'
    known.touch(mode=0o600, exist_ok=True)
    args = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'IdentityAgent=none', '-o', 'PreferredAuthentications=publickey', '-o', 'ForwardAgent=no',
            '-o', 'StrictHostKeyChecking=accept-new', '-o', f'UserKnownHostsFile={known}',
            '-o', 'ConnectTimeout=4', '-o', 'ConnectionAttempts=1', '-p', str(port), '-l', username, host,
            'show configuration interfaces | display inheritance | display xml | no-more']
    return interface_configuration(bounded_command(args, 15))


def read_static_units(device):
    return read_interface_configuration(device)['units']


def classify(name, junos, allowed_units, fixed_names=None):
    if not SAFE_NAME.fullmatch(name) or FORBIDDEN.match(name):
        return None
    if fixed_names is not None and name not in fixed_names:
        return None
    if junos:
        if PHYSICAL.fullmatch(name):
            return 'physical'
        if LAG.fullmatch(name):
            return 'lag'
        if name in allowed_units:
            return 'unit'
        if name in {'irb', 'lo0', 'vlan', 'st0'} and any(unit.startswith(name + '.') for unit in allowed_units):
            return 'virtual'
        return None
    if '.' in name:
        return 'unit' if fixed_names is not None and name in fixed_names else None
    return 'physical'


def discover(device, previous=None):
    previous = previous or {}
    snmp = Snmp(device)
    table = snmp.query([IF_NAME], walk=True)
    if not table or len(table) > 20000:
        raise RuntimeError('Interface name table empty or exceeds 20000 entries; previous inventory preserved')
    profile = device.get('ssh_profile')
    junos = profile == 'junos' if profile and profile != 'auto' else (device.get('os_name') or '').strip().lower() == 'junos'
    verified = not junos
    allowed = set()
    aggregates = {}
    aggregate_checked_at = None
    warning = None
    if junos:
        try:
            configuration = read_interface_configuration(device)
            allowed = configuration['units']
            aggregates = configuration['aggregates']
            aggregate_checked_at = int(time.time())
            verified = True
        except (ValueError, RuntimeError, ET.ParseError):
            allowed = {name for name, port in previous.items() if port.get('kind') == 'unit' and port.get('static_verified')}
            warning = 'Конфигурация интерфейсов не подтверждена по SSH; предыдущие юниты и состав AE сохранены'
    fixed = set(device.get('fixed_ports', [])) if not device.get('discover_ports', True) else None
    selected = []
    for oid, name in table.items():
        if not oid.startswith(IF_NAME + '.'):
            continue
        kind = classify(name, junos, allowed, fixed)
        if kind:
            selected.append({'name': name, 'index': int(oid.rsplit('.', 1)[1]), 'kind': kind})
    if len(selected) > MAX_INTERFACES:
        raise RuntimeError('More than 1000 selected interfaces; previous inventory preserved')
    ports = {}
    for start in range(0, len(selected), 6):
        chunk = selected[start:start + 6]
        values = snmp.query([base + '.' + str(port['index']) for port in chunk for base in (IF_TYPE, IF_SPEED, IF_ALIAS)])
        for port in chunk:
            suffix = '.' + str(port['index'])
            try:
                if_type = int(values.get(IF_TYPE + suffix, '0'))
                speed = int(values.get(IF_SPEED + suffix, '0')) * 1000000
            except ValueError:
                continue
            if not junos:
                if if_type == 161:
                    port['kind'] = 'lag'
                elif if_type != 6 and port['kind'] != 'unit':
                    continue
            port.update(speed_bps=speed or None, description=values.get(IF_ALIAS + suffix, '')[:255],
                        parent=port['name'].rsplit('.', 1)[0] if port['kind'] == 'unit' else None,
                        static_verified=verified if port['kind'] == 'unit' else True, present=True)
            if port['kind'] == 'unit' and not verified:
                port['static_verified'] = True  # Only previously verified names reached this point.
            if junos and port['kind'] == 'physical':
                if verified:
                    port.update(aggregate=aggregates.get(port['name']), aggregate_checked_at=aggregate_checked_at)
                else:
                    old = previous.get(port['name'], {})
                    if old.get('aggregate_checked_at'):
                        port.update(aggregate=old.get('aggregate'), aggregate_checked_at=old['aggregate_checked_at'])
            ports[port['name']] = port
    if not ports:
        raise RuntimeError('No eligible interfaces returned; previous inventory preserved')
    return ports, {'static_verified': verified, 'message': warning, 'name_table_count': len(table), 'selected_count': len(ports)}
