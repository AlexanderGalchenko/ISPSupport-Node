"""Opt-in node-local integration fixture. No customer endpoint is contacted."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from zabbix_api import Zabbix, SETTINGS
from zabbix_sync import sync_host, sync_items, item_key
from interface_discovery import discover, IF_NAME, IF_TYPE, IF_ALIAS, IF_SPEED
from port_history import history


def length(size):
    if size < 128:
        return bytes([size])
    value = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([128 + len(value)]) + value


def tlv(tag, content):
    return bytes([tag]) + length(len(content)) + content


def integer(value, tag=2):
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    if data[0] & 128:
        data = b'\x00' + data
    return tlv(tag, data)


def oid(name):
    parts = [int(x) for x in name.strip('.').split('.')]
    data = bytes([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        block = [value & 127]
        value >>= 7
        while value:
            block.insert(0, 128 + (value & 127))
            value >>= 7
        data += bytes(block)
    return tlv(6, data)


def parse(data, pos=0):
    tag, size = data[pos], data[pos + 1]
    pos += 2
    if size & 128:
        count = size & 127
        size = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    return tag, data[pos:pos + size], pos + size


def decode_oid(data):
    parts = [data[0] // 40, data[0] % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) + (byte & 127)
        if byte < 128:
            parts.append(value)
            value = 0
    return tuple(parts)


class Agent:
    def __init__(self, address):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, 0))
        self.socket.settimeout(.2)
        self.running = True
        self.started = time.monotonic()
        self.requests = 0
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def objects(self):
        elapsed = time.monotonic() - self.started
        values = {'.1.3.6.1.2.1.1.3.0': integer(int(elapsed * 100), 0x43)}
        for index, name in ((101, 'et-0/0/0'), (102, 'et-0/0/0.100'), (103, 'demux0.12345')):
            values[IF_NAME + '.' + str(index)] = tlv(4, name.encode())
            values[IF_ALIAS + '.' + str(index)] = tlv(4, b'Local integration fixture')
            values[IF_TYPE + '.' + str(index)] = integer(6)
            values[IF_SPEED + '.' + str(index)] = integer(100000, 0x42)
            for column in (7, 8):
                values[f'.1.3.6.1.2.1.2.2.1.{column}.{index}'] = integer(1)
            for column in (14, 20):
                values[f'.1.3.6.1.2.1.2.2.1.{column}.{index}'] = integer(0, 0x41)
            values[f'.1.3.6.1.2.1.31.1.1.1.6.{index}'] = integer(2**40 + int(elapsed * 1250000000), 0x46)
            values[f'.1.3.6.1.2.1.31.1.1.1.10.{index}'] = integer(2**40 + int(elapsed * 625000000), 0x46)
        return {tuple(int(p) for p in key.strip('.').split('.')): value for key, value in values.items()}

    def serve(self):
        while self.running:
            try:
                packet, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                _, message, _ = parse(packet)
                _, version, pos = parse(message)
                _, community, pos = parse(message, pos)
                pdu_tag, pdu, _ = parse(message, pos)
                _, request_id, pos = parse(pdu)
                _, _, pos = parse(pdu, pos)
                _, repetitions, pos = parse(pdu, pos)
                _, bindings, _ = parse(pdu, pos)
                requested, offset = [], 0
                while offset < len(bindings):
                    _, binding, offset = parse(bindings, offset)
                    _, encoded_oid, _ = parse(binding)
                    requested.append(decode_oid(encoded_oid))
                objects = self.objects()
                response = []
                for key in requested:
                    if pdu_tag == 0xa0:
                        response.append(tlv(0x30, oid('.'.join(map(str, key))) + objects.get(key, tlv(0x81, b''))))
                    else:
                        following = [candidate for candidate in sorted(objects) if candidate > key]
                        count = min(int.from_bytes(repetitions, 'big'), 25) if pdu_tag == 0xa5 else 1
                        for candidate in following[:count]:
                            response.append(tlv(0x30, oid('.'.join(map(str, candidate))) + objects[candidate]))
                        if not following:
                            response.append(tlv(0x30, oid('.'.join(map(str, key))) + tlv(0x82, b'')))
                body = tlv(0x30, tlv(2, version) + tlv(4, community) + tlv(0xa2, tlv(2, request_id) + integer(0) + integer(0) + tlv(0x30, b''.join(response))))
                self.socket.sendto(body, peer)
                self.requests += 1
            except Exception:
                self.running = False
                raise

    def close(self):
        self.running = False
        self.thread.join(1)
        self.socket.close()


def main():
    address = subprocess.check_output(['docker', 'network', 'inspect', 'ispsupport-zabbix_default', '--format', '{{(index .IPAM.Config 0).Gateway}}'], text=True).strip()
    agent = Agent(address)
    api = Zabbix.local()
    group_id = json.loads(SETTINGS.read_text())['group_id']
    device = {'id': 900000000, 'host': address, 'name': 'Temporary local SNMP test', 'client_operator_id': 1, 'os_name': 'Junos', 'snmp_port': agent.socket.getsockname()[1], 'snmp_community': 'local-fixture-only', 'discover_ports': True}
    entry = None
    try:
        with patch('interface_discovery.read_static_units', return_value={'et-0/0/0.100'}):
            ports, _ = discover(device)
        assert set(ports) == {'et-0/0/0', 'et-0/0/0.100'}, 'Discovery filter failed'
        entry = sync_host(api, {'company_id': 11}, device, {}, group_id)
        entry['ports'] = sync_items(api, entry, ports)
        items = api.call('item.get', {'hostids': [entry['host_id']], 'output': ['itemid']})
        api.call('item.update', [{'itemid': row['itemid'], 'delay': '5s'} for row in items])
        subprocess.run(['docker', 'exec', 'ispsupport-zabbix-server-1', 'zabbix_server', '-R', 'config_cache_reload'], check=True, stdout=subprocess.DEVNULL)
        for attempt in range(50):
            time.sleep(2)
            graph = history(api, device['id'], 'et-0/0/0', '1h')
            valid = [point for point in graph['points'] if point['rx'] is not None and point['tx'] is not None]
            if valid:
                last = valid[-1]
                assert 8e9 < last['rx'] < 12e9, last
                assert 4e9 < last['tx'] < 6e9, last
                break
        else:
            raise RuntimeError('Zabbix did not collect fixture traffic within 100 seconds')
        old_id = api.call('item.get', {'hostids': [entry['host_id']], 'filter': {'key_': item_key('et-0/0/0', 'rx')}, 'output': ['itemid']})[0]['itemid']
        sync_items(api, entry, {'et-0/0/0.100': ports['et-0/0/0.100']})
        missing = api.call('item.get', {'itemids': [old_id], 'output': ['status']})[0]
        assert missing['status'] == '1', 'Missing interface was not disabled'
        retained = history(api, device['id'], 'et-0/0/0', '1h')
        assert any(point['rx'] is not None for point in retained['points']), 'History lost on disappearance'
        print(json.dumps({'integration': 'passed', 'selected_interfaces': 2, 'subscriber_interfaces': 0, 'rx_bps': round(last['rx']), 'tx_bps': round(last['tx']), 'snmp_requests': agent.requests, 'missing_port_history': 'preserved'}))
    finally:
        if entry:
            api.call('host.delete', [entry['host_id']])
        agent.close()


if __name__ == '__main__':
    main()
