import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
from zabbix_sync import item_definition, item_key, push_host_snmp, sync_subscribers


class HostSnmpTest(unittest.TestCase):
    def test_transport_change_keeps_keys_and_counter_preprocessing(self):
        port = {'name': 'Te0/1/0', 'index': 8, 'speed_bps': 10000000000}
        native = item_definition('1', '2', port, 'rx')
        host = item_definition('1', '2', port, 'rx', True)
        self.assertEqual(native['key_'], host['key_'])
        self.assertEqual(native['preprocessing'], host['preprocessing'])
        self.assertEqual(host['type'], 2)
        self.assertEqual(host['interfaceid'], '0')
        self.assertEqual(host['snmp_oid'], '')

    def test_existing_subscriber_item_switches_transport_without_losing_history(self):
        api = Mock(); api.call.return_value = [{'itemid': '9'}]
        entry = {'host_id': '1', 'interface_id': '2', 'subscriber_enabled': True,
                 'subscriber_oid': '.1.3.6.1.4.1.9.9.194.1.1.1.0'}
        sync_subscribers(api, entry, {'roles': ['bras'], 'os_name': 'Cisco IOS XE', 'poll_from_host': True})
        method, definition = api.call.call_args.args
        self.assertEqual(method, 'item.update')
        self.assertEqual(definition['itemid'], '9')
        self.assertEqual(definition['type'], 2)
        self.assertNotIn('hostid', definition)

    def test_push_uses_raw_counters_and_preserves_zero_without_inventing_missing_values(self):
        api = Mock()
        api.call.side_effect = [[{'itemid': '1', 'key_': 'isp.device.subscribers'},
                                 {'itemid': '2', 'key_': item_key('Te0/1/0', 'rx')},
                                 {'itemid': '3', 'key_': item_key('Te0/1/0', 'tx')}],
                                {'response': 'success', 'data': [{'itemid': '1'}, {'itemid': '2'}]}]
        entry = {'host_id': '7', 'subscriber_enabled': True, 'ports': {'Te0/1/0': {'index': 8, 'present': True}}}
        with patch('zabbix_sync.Snmp') as client:
            client.return_value.query.return_value = {'.1.3.6.1.4.1.9.9.194.1.1.1.0': '0', '.1.3.6.1.2.1.31.1.1.1.6.8': '123456789', '.1.3.6.1.2.1.31.1.1.1.10.8': 'No Such Instance'}
            push_host_snmp(api, entry, {'roles': ['bras'], 'os_name': 'Cisco IOS XE'})
        method, data = api.call.call_args.args
        self.assertEqual(method, 'history.push')
        self.assertEqual({r['itemid']: r['value'] for r in data}, {'1': '0', '2': '123456789'})
        self.assertGreater(entry['host_poll_last_success'], 0)

    def test_partial_api_rejection_does_not_claim_success(self):
        api = Mock(); api.call.side_effect = [[{'itemid': '1', 'key_': 'isp.device.subscribers'}], {'response': 'success', 'data': [{'itemid': '1', 'error': 'unavailable'}]}]
        entry = {'host_id': '7', 'subscriber_enabled': True}
        with patch('zabbix_sync.Snmp') as client:
            client.return_value.query.return_value = {'.1.3.6.1.4.1.9.9.194.1.1.1.0': '12'}
            with self.assertRaises(RuntimeError):
                push_host_snmp(api, entry, {'roles': ['bras'], 'os_name': 'Cisco IOS XE'})
        self.assertNotIn('host_poll_last_success', entry)
