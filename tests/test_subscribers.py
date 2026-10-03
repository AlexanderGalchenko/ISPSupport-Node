import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from zabbix_sync import sync_subscribers,subscriber_snapshot
from port_history import history
class Api:
    def __init__(self,rows=None): self.rows=rows or [];self.calls=[]
    def call(self,method,params):
        self.calls.append((method,params))
        if method=='host.get':return [{'hostid':'10'}]
        if method=='history.get':return [{'itemid':'20','clock':'1000','value':'0'}]
        if method=='item.get' and params.get('output')==['itemid','key_']:return [{'itemid':'20','key_':'isp.device.subscribers'}]
        return self.rows
class SubscriberTest(unittest.TestCase):
    def test_bras_is_a_gauge_not_a_counter_derivative(self):
        api=Api();entry={'host_id':'10','interface_id':'11'}
        sync_subscribers(api,entry,{'roles':['bras','border'],'os_name':'Junos'})
        definition=api.calls[-1][1]
        self.assertEqual(definition['snmp_oid'],'.1.3.6.1.4.1.2636.3.64.1.1.1.2.0')
        self.assertEqual(definition['value_type'],3)
        self.assertNotIn('preprocessing',definition)
        self.assertTrue(entry['subscriber_enabled'])
    def test_removing_role_disables_item_and_keeps_history(self):
        api=Api([{'itemid':'20'}]);entry={'host_id':'10','interface_id':'11','subscriber_enabled':True}
        sync_subscribers(api,entry,{'roles':['border'],'os_name':'Junos'})
        self.assertEqual(api.calls[-1],('item.update',{'itemid':'20','status':1}))
        self.assertFalse(entry['subscriber_enabled'])
    def test_unsupported_devices_do_not_receive_juniper_oid(self):
        api=Api();sync_subscribers(api,{'host_id':'10','interface_id':'11'},{'roles':['bras'],'os_name':'IOS'})
        self.assertEqual(api.calls,[])
    def test_zero_subscribers_is_published_and_stale_state_is_excluded(self):
        api=Api([{'hostid':'10','lastvalue':'0','lastclock':'1000','state':'0','status':'0'}])
        config={'snmp_devices':[{'id':4,'roles':['bras']}]} 
        entries={'4':{'host_id':'10','enabled':True,'subscriber_enabled':True}}
        self.assertEqual(subscriber_snapshot(api,config,entries),[{'id':4,'value':0,'clock':1000}])
        api.rows[0]['state']='1';self.assertEqual(subscriber_snapshot(api,config,entries),[])
    def test_subscriber_history_uses_unsigned_gauges_and_keeps_zero(self):
        api=Api();result=history(api,4,'subscribers','1h',now=1100,device_metric=True)
        self.assertEqual(next(p for m,p in api.calls if m=='history.get')['history'],3)
        self.assertEqual([p['rx'] for p in result['points'] if p['rx'] is not None],[0.0])
if __name__=='__main__':unittest.main()
