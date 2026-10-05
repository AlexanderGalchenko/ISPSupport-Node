import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import lldp_collect as lldp

LOCAL = '''<rpc-reply><lldp-local-info><lldp-local-chassis-id>02:00:00:00:00:01</lldp-local-chassis-id>
<lldp-local-system-name>router-lab</lldp-local-system-name>
<lldp-local-management-address-address>192.0.2.1</lldp-local-management-address-address>
<lldp-local-interface-info><lldp-local-interface-name>et-0/0/2</lldp-local-interface-name>
<lldp-parent-local-interface-name>ae0</lldp-parent-local-interface-name>
<lldp-local-interface-id>594</lldp-local-interface-id></lldp-local-interface-info></lldp-local-info></rpc-reply>'''
REMOTE = '''<rpc-reply xmlns="urn:lab"><lldp-neighbors-information><lldp-neighbor-information>
<lldp-local-interface>et-0/0/2</lldp-local-interface><lldp-local-parent-interface-name>ae0</lldp-local-parent-interface-name>
<lldp-remote-chassis-id-subtype>Mac address</lldp-remote-chassis-id-subtype><lldp-remote-chassis-id>0200-0000-0002</lldp-remote-chassis-id>
<lldp-remote-port-id>100GE0/0/2</lldp-remote-port-id><lldp-remote-port-id-subtype>Interface name</lldp-remote-port-id-subtype>
<lldp-remote-system-name>switch-lab</lldp-remote-system-name><lldp-remote-management-address>198.51.100.2</lldp-remote-management-address>
</lldp-neighbor-information></lldp-neighbors-information></rpc-reply>'''
HWLOCAL = '''System information
Chassis ID :0200-0000-0002
System name :switch-lab
Management Address :IP:198.51.100.2 MAC:0200-0000-0002
Total Neighbors :2
Interface 100GE0/0/2:
Port ID :100GE0/0/2
'''
HWREMOTE = '''100GE0/0/2 has 2 neighbor(s):
Neighbor index :1
Chassis type :MAC address
Chassis ID :0200-0000-0001
Port ID type :Locally assigned
Port ID :594
Port description :uplink description is not the port name
System name :router-lab
Management address value :192.0.2.1
Neighbor index :2
Chassis type :MAC address
Chassis ID :0200-0000-0003
Port ID type :Interface name
Port ID :ether2 - subscriber trunk
Management address value :2001:db8::1
Management address value :192.0.2.3
'''


class LldpTest(unittest.TestCase):
    def test_junos_xml_and_numeric_port_mapping_preserve_physical_and_parent(self):
        data = lldp.parse_junos(LOCAL, REMOTE)
        self.assertEqual('594', data['identity']['ports'][0]['port_id'])
        self.assertEqual('ae0', data['neighbors'][0]['local_parent'])
        self.assertEqual('02:00:00:00:00:02', data['neighbors'][0]['chassis_id'])
        self.assertEqual(['198.51.100.2'], data['neighbors'][0]['management_addresses'])

    def test_multiple_huawei_neighbors_and_management_addresses_are_not_lost(self):
        data = lldp.parse_huawei(HWLOCAL, HWREMOTE)
        self.assertEqual(2, len(data['neighbors']))
        self.assertEqual('594', data['neighbors'][0]['port_id'])
        self.assertEqual('ether2 - subscriber trunk', data['neighbors'][1]['port_id'])
        self.assertEqual(['2001:db8::1', '192.0.2.3'], data['neighbors'][1]['management_addresses'])

    def test_truncated_denied_and_unknown_outputs_are_not_empty_success(self):
        for content in [HWREMOTE.replace('2 neighbor(s)', '3 neighbor(s)'), 'Error: permission denied', 'unsupported output']:
            with self.assertRaises(ValueError):
                lldp.parse_huawei(HWLOCAL, content)
        for content in [REMOTE[:-12], '<rpc-reply><rpc-error/></rpc-reply>', '<!DOCTYPE x>'+REMOTE]:
            with self.assertRaises((ValueError, lldp.ET.ParseError)):
                lldp.parse_junos(LOCAL, content)

    def test_valid_empty_snapshot_is_distinct_from_collection_failure(self):
        self.assertEqual([], lldp.parse_junos(LOCAL, '<rpc-reply><lldp-neighbors-information/></rpc-reply>')['neighbors'])
        self.assertEqual([], lldp.parse_huawei(HWLOCAL.replace('Total Neighbors :2', 'Total Neighbors :0'), '')['neighbors'])

    def test_injected_address_or_root_never_starts_transport(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(lldp, 'junos_session') as run:
            for host, user in [('192.0.2.1', 'root'), ('192.0.2.1;id', 'operator'), ('192.0.2.1', '-oProxyCommand=id')]:
                data = lldp.collect_one({'id': 1, 'host': host, 'ssh_username': user, 'ssh_profile': 'junos'}, Path(folder))
                self.assertEqual('failed', data['status'])
            run.assert_not_called()

    def test_cache_is_private_bounded_and_endpoint_changes_invalidate_it(self):
        devices = [{'id': i, 'host': '192.0.2.'+str(i), 'ssh_profile': 'junos'} for i in range(1, 7)]
        def collected(device, state):
            return {'id': device['id'], 'host': device['host'], 'status': 'ok', 'attempted_at': 10000, 'collected_at': 10000}
        with tempfile.TemporaryDirectory() as folder, patch.object(lldp.time, 'time', return_value=10001), patch.object(lldp, 'collect_one', side_effect=collected) as run:
            state = Path(folder)
            self.assertEqual(4, len(lldp.collect_cached(devices, state)))
            self.assertEqual(4, run.call_count)
            self.assertEqual(6, len(lldp.collect_cached(devices, state)))
            self.assertEqual(6, run.call_count)
            lldp.collect_cached(devices, state)
            self.assertEqual(6, run.call_count)
            devices[0]['host'] = '198.51.100.1'
            lldp.collect_cached(devices, state)
            self.assertEqual(7, run.call_count)
            self.assertEqual(0o600, (state/'lldp/1.json').stat().st_mode & 0o777)


if __name__ == '__main__':
    unittest.main()
