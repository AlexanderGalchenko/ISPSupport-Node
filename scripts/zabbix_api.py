"""Local Zabbix API access. Credentials never leave the client node."""
import json
import os
from pathlib import Path
import tempfile
import urllib.request

SETTINGS = Path('/etc/ispsupport-node/zabbix-api.json')
API_URL = 'http://127.0.0.1:18080/api_jsonrpc.php'


def private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, mode=0o750, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as handle:
        json.dump(value, handle, ensure_ascii=False)
        temporary = Path(handle.name)
    temporary.replace(path)


class Zabbix:
    def __init__(self, token=None, url=API_URL):
        self.token = token
        self.url = url

    @classmethod
    def local(cls):
        return cls(json.loads(SETTINGS.read_text())['token'])

    def call(self, method, params=None):
        body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params if params is not None else {}}
        headers = {'Content-Type': 'application/json-rpc'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request(self.url, json.dumps(body).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read(32 * 1024 * 1024 + 1)
        if len(raw) > 32 * 1024 * 1024:
            raise RuntimeError('Zabbix response exceeded size limit')
        data = json.loads(raw)
        if 'error' in data:
            # Do not include API parameters or secret values in exceptions/logs.
            raise RuntimeError('Zabbix API rejected ' + method + ': ' + str(data['error'].get('code', 'error')))
        return data['result']
