import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from interface_discovery import Snmp, classify, static_units, interface_configuration, discover, IF_NAME, IF_TYPE, IF_SPEED, IF_ALIAS
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

    def test_configuration_reports_physical_members_and_ignores_inactive_bundles(self):
        xml = """<rpc-reply xmlns="urn:junos"><configuration><interfaces>
        <interface><name>et-0/0/1</name><ether-options><ieee-802.3ad><bundle>ae0</bundle></ieee-802.3ad></ether-options></interface>
        <interface><name>xe-1/1/0</name><gigether-options><ieee-802.3ad><bundle>ae1</bundle></ieee-802.3ad></gigether-options></interface>
        <interface><name>xe-2/1/0</name><gigether-options><ieee-802.3ad><bundle>ae1</bundle></ieee-802.3ad></gigether-options></interface>
        <interface><name>et-0/0/2</name><ether-options inactive="inactive"><ieee-802.3ad><bundle>ae2</bundle></ieee-802.3ad></ether-options></interface>
        <interface inactive="inactive"><name>et-0/0/3</name><ether-options><ieee-802.3ad><bundle>ae3</bundle></ieee-802.3ad></ether-options></interface>
        <interface><name>ae1</name><unit><name>444</name></unit></interface>
        </interfaces></configuration></rpc-reply>"""
        data = interface_configuration(xml)
        self.assertEqual({'et-0/0/1': 'ae0', 'xe-1/1/0': 'ae1', 'xe-2/1/0': 'ae1', 'et-0/0/2': None}, data['aggregates'])
        self.assertEqual({'ae1.444'}, data['units'])

    def test_failed_configuration_read_preserves_known_aggregate_and_verified_removal_clears_it(self):
        device = {'host': '192.0.2.1', 'os_name': 'Junos', 'snmp_community': 'fixture'}
        previous = {'et-0/0/1': {'kind': 'physical', 'aggregate': 'ae0', 'aggregate_checked_at': 123}}
        responses = [{IF_NAME+'.5': 'et-0/0/1'}, {IF_TYPE+'.5': '6', IF_SPEED+'.5': '10000', IF_ALIAS+'.5': ''}]
        with patch('interface_discovery.Snmp.query', side_effect=responses), patch('interface_discovery.read_interface_configuration', side_effect=RuntimeError()):
            ports, status = discover(device, previous)
        self.assertEqual('ae0', ports['et-0/0/1']['aggregate'])
        self.assertEqual(123, ports['et-0/0/1']['aggregate_checked_at'])
        self.assertFalse(status['static_verified'])
        with patch('interface_discovery.Snmp.query', side_effect=responses), patch('interface_discovery.read_interface_configuration', return_value={'units': set(), 'aggregates': {'et-0/0/1': None}}):
            ports, status = discover(device, previous)
        self.assertIsNone(ports['et-0/0/1']['aggregate'])
        self.assertGreater(ports['et-0/0/1']['aggregate_checked_at'], 123)
        self.assertTrue(status['static_verified'])

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
