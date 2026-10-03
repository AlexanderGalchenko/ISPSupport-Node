#!/usr/bin/env python3
"""Reconcile explicit node configuration with local Zabbix; keep interface history by name."""
import fcntl
import hashlib
import ipaddress
import json
from pathlib import Path
import time
from interface_discovery import discover, MAX_INTERFACES
from zabbix_api import Zabbix, SETTINGS, private_json

STATE = Path('/var/lib/ispsupport-node/zabbix-inventory.json')
CONFIG = Path('/etc/ispsupport-node/node.json')
METRICS = {
    'rx': ('.1.3.6.1.2.1.31.1.1.1.6', 0, 'bps'),
    'tx': ('.1.3.6.1.2.1.31.1.1.1.10', 0, 'bps'),
    'oper': ('.1.3.6.1.2.1.2.2.1.8', 3, ''),
    'admin': ('.1.3.6.1.2.1.2.2.1.7', 3, ''),
    'speed': ('.1.3.6.1.2.1.31.1.1.1.15', 3, 'bps'),
    'in_errors': ('.1.3.6.1.2.1.2.2.1.14', 0, 'eps'),
    'out_errors': ('.1.3.6.1.2.1.2.2.1.20', 0, 'eps'),
}


def item_key(name, metric):
    return 'isp.if.' + metric + '[' + hashlib.sha256(name.encode()).hexdigest()[:24] + ']'


def host_name(device_id):
    return 'isp-device-' + str(int(device_id))


def item_definition(host_id, interface_id, port, metric):
    oid, value_type, units = METRICS[metric]
    preprocessing = []
    if metric in ('rx', 'tx', 'in_errors', 'out_errors'):
        preprocessing.append({'type': 10, 'params': '', 'error_handler': 1})
    if metric in ('rx', 'tx'):
        preprocessing.append({'type': 1, 'params': '8', 'error_handler': 1})
        if port.get('speed_bps'):
            preprocessing.append({'type': 13, 'params': '0\n' + str(int(port['speed_bps'] * 1.2)), 'error_handler': 1})
    if metric == 'speed':
        preprocessing.append({'type': 1, 'params': '1000000', 'error_handler': 1})
    if preprocessing:
        # Changing the ifIndex changes preprocessing, resetting the previous-counter cache.
        preprocessing.append({'type': 21, 'params': 'return value; // ifIndex ' + str(port['index']), 'error_handler': 0})
    return {'hostid': str(host_id), 'interfaceid': str(interface_id), 'name': port['name'] + ': ' + metric,
            'key_': item_key(port['name'], metric), 'type': 20, 'value_type': value_type,
            'snmp_oid': oid + '.' + str(port['index']), 'delay': '60s', 'history': '14d', 'trends': '365d',
            'units': units, 'status': 0, 'preprocessing': preprocessing,
            'tags': [{'tag': 'component', 'value': 'interfaces'}, {'tag': 'interface', 'value': port['name']},
                     {'tag': 'isp:managed', 'value': '1'}, {'tag': 'metric', 'value': metric}]}


def sync_host(api, config, device, old, group_id):
    identity = host_name(device['id'])
    host = str(ipaddress.ip_address(device['host']))
    fingerprint = hashlib.sha256(json.dumps(device, sort_keys=True).encode()).hexdigest()
    if old.get('host_id') and old.get('config_hash') == fingerprint and old.get('enabled'):
        return old
    found = api.call('host.get', {'filter': {'host': identity}, 'output': ['hostid'], 'selectInterfaces': ['interfaceid', 'type']})
    details = {'version': 2, 'bulk': 1, 'community': '{$SNMP_COMMUNITY}'}
    interface = {'type': 2, 'main': 1, 'useip': 1, 'ip': host, 'dns': '', 'port': str(device.get('snmp_port', 161)), 'details': details}
    settings = {'name': (device.get('name') or identity)[:128], 'status': 0,
                'macros': [{'macro': '{$SNMP_COMMUNITY}', 'value': device['snmp_community'], 'type': 1}],
                'tags': [{'tag': 'isp:managed', 'value': '1'}, {'tag': 'isp:company', 'value': str(config['company_id'])},
                         {'tag': 'isp:operator', 'value': str(device['client_operator_id'])}]}
    if found:
        host_id = found[0]['hostid']
        interfaces = [row for row in found[0]['interfaces'] if int(row['type']) == 2]
        if interfaces:
            interface_id = interfaces[0]['interfaceid']
            api.call('hostinterface.update', {'interfaceid': interface_id, **interface})
        else:
            interface_id = api.call('hostinterface.create', {'hostid': host_id, **interface})['interfaceids'][0]
        api.call('host.update', {'hostid': host_id, **settings})
    else:
        host_id = api.call('host.create', {'host': identity, 'groups': [{'groupid': group_id}], 'interfaces': [interface], **settings})['hostids'][0]
        interface_id = api.call('hostinterface.get', {'hostids': [host_id], 'output': ['interfaceid']})[0]['interfaceid']
    return {**old, 'host_id': host_id, 'interface_id': interface_id, 'config_hash': fingerprint, 'enabled': True, 'last_attempt': 0}


def sync_subscribers(api, entry, device):
    wanted = 'bras' in device.get('roles', []) and (device.get('os_name') or '').lower() == 'junos'
    if entry.get('subscriber_enabled', False) is wanted:
        return
    items = api.call('item.get', {'hostids': [entry['host_id']], 'filter': {'key_': 'isp.device.subscribers'}, 'output': ['itemid']})
    definition = {'name': 'Активные абонентские сессии', 'key_': 'isp.device.subscribers',
                  'hostid': entry['host_id'], 'interfaceid': entry['interface_id'], 'type': 20, 'value_type': 3,
                  'snmp_oid': '.1.3.6.1.4.1.2636.3.64.1.1.1.2.0', 'delay': '60s', 'history': '14d', 'trends': '365d',
                  'status': 0, 'tags': [{'tag': 'component', 'value': 'subscribers'}, {'tag': 'isp:managed', 'value': '1'}]}
    if wanted:
        api.call('item.update', {'itemid': items[0]['itemid'], **definition}) if items else api.call('item.create', definition)
    elif items:
        api.call('item.update', {'itemid': items[0]['itemid'], 'status': 1})
    entry['subscriber_enabled'] = wanted


def subscriber_snapshot(api, config, entries):
    configured = {str(d['id']): d for d in config.get('snmp_devices', config.get('devices', [])) if 'bras' in d.get('roles', [])}
    hosts = {str(e['host_id']): key for key, e in entries.items() if key in configured and e.get('enabled') and e.get('subscriber_enabled')}
    if not hosts:
        return []
    rows = api.call('item.get', {'hostids': list(hosts), 'filter': {'key_': 'isp.device.subscribers'},
                              'output': ['hostid', 'lastvalue', 'lastclock', 'state', 'status']})
    return [{'id': int(hosts[r['hostid']]), 'value': int(r['lastvalue']), 'clock': int(r['lastclock'])}
            for r in rows if r.get('state') == '0' and r.get('status') == '0' and int(r.get('lastclock', 0)) > 0]


def sync_items(api, entry, discovered):
    old_ports = entry.get('ports', {})
    existing = api.call('item.get', {'hostids': [entry['host_id']], 'output': ['itemid', 'key_', 'status'], 'search': {'key_': 'isp.if.'}, 'startSearch': True})
    by_key = {row['key_']: row for row in existing}
    create, update, desired = [], [], set()
    for name, port in discovered.items():
        prior = old_ports.get(name, {})
        changed = prior.get('index') != port['index'] or prior.get('speed_bps') != port.get('speed_bps')
        for metric in METRICS:
            item = item_definition(entry['host_id'], entry['interface_id'], port, metric)
            key = item['key_']
            desired.add(key)
            if key not in by_key:
                create.append(item)
            elif changed or by_key[key]['status'] != '0':
                item.pop('hostid')
                update.append({'itemid': by_key[key]['itemid'], **item})
    for row in existing:
        if row['key_'] not in desired and row['status'] != '1':
            update.append({'itemid': row['itemid'], 'status': 1})
    for values, method in ((create, 'item.create'), (update, 'item.update')):
        for start in range(0, len(values), 100):
            api.call(method, values[start:start + 100])
    now = int(time.time())
    ports = {}
    for name, port in discovered.items():
        ports[name] = {**port, 'last_seen': now}
    for name, port in old_ports.items():
        if name not in discovered:
            ports[name] = {**port, 'present': False, 'missing_since': port.get('missing_since') or now}
    if len(ports) > MAX_INTERFACES * 2:
        # Retain recent missing entries; their Zabbix items/history are never deleted.
        missing = sorted((p for p in ports.values() if not p['present']), key=lambda p: p.get('last_seen', 0), reverse=True)
        ports = {p['name']: p for p in list(discovered.values()) + missing[:MAX_INTERFACES]}
    return ports


def reconcile(config, state, api, group_id):
    if 'snmp_devices' not in config:
        return state
    now = int(time.time())
    roster = {str(d['id']): d for d in config['snmp_devices'] if d.get('snmp_community')}
    entries = state.get('devices', {})
    # This also handles a crash after host creation but before the inventory file was saved.
    hosts = api.call('host.get', {'groupids': [group_id], 'output': ['hostid', 'host', 'status']})
    for host in hosts:
        if host['host'].startswith('isp-device-') and host['host'][11:] not in roster and host['status'] != '1':
            api.call('host.update', {'hostid': host['hostid'], 'status': 1})
    for device_id, entry in entries.items():
        if device_id not in roster:
            entry['enabled'] = False
    budget = 4
    for device_id, device in sorted(roster.items(), key=lambda pair: entries.get(pair[0], {}).get('last_attempt', 0)):
        entry = entries.get(device_id, {})
        try:
            entry = sync_host(api, config, device, entry, group_id)
            sync_subscribers(api, entry, device)
            interval = 300 if entry.get('error') else 900
            if budget and now - entry.get('last_attempt', 0) >= interval:
                budget -= 1
                entry['last_attempt'] = now
                ports, information = discover(device, entry.get('ports'))
                entry['ports'] = sync_items(api, entry, ports)
                entry.update(last_success=now, discovery=information, error=None)
        except Exception as error:
            # Never serialize command output, device configuration, or API parameters.
            entry['error'] = 'Обнаружение не завершено: проверьте доступ SNMP и состояние Zabbix. Предыдущие порты и история сохранены.'
            entry['last_attempt'] = now
        entries[device_id] = entry
    return {'config_version': config['config_version'], 'updated_at': now, 'devices': entries}


def snapshot(config):
    if not SETTINGS.exists():
        return {'status': 'not_installed', 'devices': []}
    if not STATE.exists():
        return {'status': 'starting', 'devices': []}
    state = json.loads(STATE.read_text())
    if state.get('config_version') != config['config_version']:
        return {'status': 'config_pending', 'devices': []}
    api = Zabbix.local()
    results = []
    for device in config.get('devices', []):
        entry = state.get('devices', {}).get(str(device['id']), {})
        if not entry.get('host_id') or not entry.get('enabled'):
            continue
        rows = api.call('item.get', {'hostids': [entry['host_id']], 'output': ['key_', 'lastvalue', 'lastclock', 'state', 'status'], 'search': {'key_': 'isp.if.'}, 'startSearch': True})
        items = {row['key_']: row for row in rows}
        ports = []
        for name, port in entry.get('ports', {}).items():
            value = {k: port.get(k) for k in ('name', 'index', 'kind', 'parent', 'aggregate', 'aggregate_checked_at', 'speed_bps', 'description', 'static_verified', 'present', 'last_seen', 'missing_since')}
            metrics = {}
            for metric in METRICS:
                item = items.get(item_key(name, metric), {})
                clock = int(item.get('lastclock', 0))
                if clock and item.get('state') == '0' and item.get('status') == '0' and port.get('present'):
                    metrics[metric] = {'value': float(item['lastvalue']), 'clock': clock}
            value['metrics'] = metrics
            ports.append(value)
        results.append({'id': device['id'], 'checked_at': entry.get('last_success'), 'message': entry.get('error') or entry.get('discovery', {}).get('message'), 'ports': ports})
    return {'status': 'ready', 'updated_at': state['updated_at'], 'devices': results, 'subscribers': subscriber_snapshot(api, config, state.get('devices', {}))}


def main():
    with open('/run/lock/ispsupport-zabbix-sync.lock', 'w') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        config = json.loads(CONFIG.read_text())
        settings = json.loads(SETTINGS.read_text())
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
        updated = reconcile(config, state, Zabbix.local(), settings['group_id'])
        private_json(STATE, updated)
        print('Zabbix sync: ' + str(sum(bool(d.get('enabled')) for d in updated.get('devices', {}).values())) + ' configured devices')


if __name__ == '__main__':
    main()
