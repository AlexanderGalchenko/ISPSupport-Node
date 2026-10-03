#!/usr/bin/env python3
import json
from pathlib import Path
import secrets
import time
import urllib.error
from zabbix_api import Zabbix, SETTINGS, private_json


def main():
    api = Zabbix()
    for attempt in range(90):
        try:
            version = api.call('apiinfo.version')
            break
        except (urllib.error.URLError, json.JSONDecodeError, RuntimeError):
            if attempt == 89:
                raise RuntimeError('Zabbix API startup timeout')
            time.sleep(2)
    if not str(version).startswith('7.0.'):
        raise RuntimeError('Expected Zabbix 7.0 LTS')
    if SETTINGS.exists():
        existing = Zabbix.local()
        existing.call('hostgroup.get', {'output': ['groupid'], 'filter': {'name': 'ISP Support managed'}})
        print('Zabbix ' + version + ': existing API credentials verified')
        return
    recovery = Path('/etc/ispsupport-node/zabbix-admin.json')
    if not recovery.exists():
        private_json(recovery, {'password': secrets.token_urlsafe(32) + 'aA1!'})
    admin_password = json.loads(recovery.read_text())['password']
    try:
        api.token = api.call('user.login', {'username': 'Admin', 'password': admin_password})
    except RuntimeError:
        api.token = api.call('user.login', {'username': 'Admin', 'password': 'zabbix'})
        api.call('user.update', {'userid': '1', 'passwd': admin_password, 'current_passwd': 'zabbix'})
        api.token = None
        api.token = api.call('user.login', {'username': 'Admin', 'password': admin_password})
    groups = api.call('hostgroup.get', {'filter': {'name': 'ISP Support managed'}})
    group_id = groups[0]['groupid'] if groups else api.call('hostgroup.create', {'name': 'ISP Support managed'})['groupids'][0]
    usergroups = api.call('usergroup.get', {'filter': {'name': 'ISP Support automation'}})
    permissions = {'name': 'ISP Support automation', 'hostgroup_rights': [{'id': group_id, 'permission': 3}]}
    if usergroups:
        usergroup_id = usergroups[0]['usrgrpid']
    else:
        usergroup_id = api.call('usergroup.create', permissions)['usrgrpids'][0]
    users = api.call('user.get', {'filter': {'username': 'isp-node-api'}})
    if users:
        user_id = users[0]['userid']
    else:
        user_id = api.call('user.create', {'username': 'isp-node-api', 'passwd': secrets.token_urlsafe(32) + 'aA1!', 'roleid': '2', 'usrgrps': [{'usrgrpid': usergroup_id}]})['userids'][0]
    token_id = api.call('token.create', {'name': 'ISP Support node automation', 'userid': user_id})['tokenids'][0]
    token = api.call('token.generate', [token_id])[0]['token']
    private_json(SETTINGS, {'token': token, 'group_id': group_id, 'api_url': api.url, 'version': version})
    # Disable the bundled self-monitoring host until a matching agent is explicitly configured.
    default = api.call('host.get', {'filter': {'host': 'Zabbix server'}, 'output': ['hostid']})
    for host in default:
        api.call('host.update', {'hostid': host['hostid'], 'status': 1})
    api.call('housekeeping.update', {'hk_history_global': 1, 'hk_history': '14d', 'hk_trends_global': 1, 'hk_trends': '365d'})
    api.call('user.logout', [])
    print('Zabbix ' + version + ': API configured; default password rotated; history 14d, trends 365d')


if __name__ == '__main__':
    main()
