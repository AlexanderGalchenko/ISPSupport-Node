import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from interface_discovery import Snmp, classify, static_units
from port_history import aggregate
from zabbix_sync import item_definition, item_key, reconcile, snapshot
from zabbix_api import private_json


class PortMonitoringTest(unittest.TestCase):
    def test_junos_static_units_exclude_inactive_and_subscriber_interfaces(self):
        xml = '''<rpc-reply xmlns="urn:junos"><configuration><interfaces>
        <interface><name>et-0/0/0</name><unit><name>100</name></unit>
        <unit inactive="inactive"><name>200</name></unit></interface>
        <interface><name>demux0</name><unit><name>1000</name></unit></interface>
        </interfaces></configuration></rpc-reply>'''
        allowed = static_units(xml)
        self.assertEqual({'et-0/0/0.100'}, allowed)
        self.assertEqual('unit', classify('et-0/0/0.100', True, allowed))
        self.assertIsNone(classify('et-0/0/0.200', True, allowed))
        self.assertIsNone(classify('demux0.1000', True, allowed))

    def test_fixed_inventory_and_root_ssh_are_not_used_for_unknown_interfaces(self):
        self.assertIsNone(classify('et-0/0/1', True, set(), {'et-0/0/0'}))
        with self.assertRaises(ValueError):
            static_units('<!DOCTYPE x><rpc-reply/>')

    def test_ifindex_change_preserves_item_identity_and_resets_counter_preprocessing(self):
        a = item_definition('1', '2', {'name': 'et-0/0/0', 'index': 10, 'speed_bps': 100000000000}, 'rx')
        b = item_definition('1', '2', {'name': 'et-0/0/0', 'index': 50, 'speed_bps': 100000000000}, 'rx')
        self.assertEqual(a['key_'], b['key_'])
        self.assertNotEqual(a['snmp_oid'], b['snmp_oid'])
        self.assertNotEqual(a['preprocessing'], b['preprocessing'])
        self.assertEqual('.1.3.6.1.2.1.31.1.1.1.6.50', b['snmp_oid'])

    def test_empty_roster_disables_old_host_without_discovery_or_history_deletion(self):
        api = Mock()
        api.call.side_effect = [[{'hostid': '20', 'host': 'isp-device-4', 'status': '0'}], {}]
        state = {'devices': {'4': {'host_id': '20', 'enabled': True, 'ports': {'et-0/0/0': {}}}}}
        with patch('zabbix_sync.discover') as discover:
            result = reconcile({'snmp_devices': [], 'config_version': 3}, state, api, '8')
            discover.assert_not_called()
        self.assertFalse(result['devices']['4']['enabled'])
        self.assertIn('et-0/0/0', result['devices']['4']['ports'])
        api.call.assert_called_with('host.update', {'hostid': '20', 'status': 1})

    def test_history_gaps_remain_null_and_trends_are_weighted(self):
        rows = [{'itemid': '1', 'clock': 120, 'value_avg': '10', 'value_max': '25', 'num': '2'},
                {'itemid': '1', 'clock': 140, 'value_avg': '40', 'value_max': '50', 'num': '1'},
                {'itemid': '2', 'clock': 120, 'value': 'nan'}]
        points = aggregate(rows, {'1': 'rx', '2': 'tx'}, 120, 240, 60)
        self.assertEqual(20, points[0]['rx'])
        self.assertEqual(50, points[0]['rx_max'])
        self.assertIsNone(points[0]['tx'])
        self.assertIsNone(points[1]['rx'])

    def test_snmp_discovery_total_time_is_bounded(self):
        client = Snmp({'host': '127.0.0.1', 'snmp_community': 'fixture'})
        client.deadline = 0
        with patch('interface_discovery.bounded_command') as run:
            with self.assertRaises(RuntimeError):
                client.query(['.1.3.6.1.2.1.1.1.0'])
            run.assert_not_called()

    def test_snapshot_does_not_publish_previous_configuration_results(self):
        with tempfile.TemporaryDirectory() as directory:
            settings, state = Path(directory) / 'api.json', Path(directory) / 'inventory.json'
            private_json(settings, {})
            private_json(state, {'config_version': 1, 'devices': {'4': {'enabled': True}}})
            with patch('zabbix_sync.SETTINGS', settings), patch('zabbix_sync.STATE', state), patch('zabbix_sync.Zabbix.local') as api:
                self.assertEqual('config_pending', snapshot({'config_version': 2})['status'])
                api.assert_not_called()


if __name__ == '__main__':
    unittest.main()
