#!/usr/bin/env python3
"""Read local Zabbix history only; never query customer devices from a graph request."""
import json
import math
import re
import sys
import time
from zabbix_api import Zabbix
from zabbix_sync import item_key, host_name

RANGES = {'1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000}


def aggregate(rows, item_ids, start, end, step):
    first = start // step * step
    buckets = {clock: {} for clock in range(first, end + 1, step)}
    for row in rows:
        metric = item_ids.get(str(row['itemid']))
        clock = int(row['clock'])
        if metric is None or clock < start or clock > end:
            continue
        value = float(row.get('value_avg', row.get('value', 0)))
        maximum = float(row.get('value_max', value))
        count = int(row.get('num', 1))
        if count < 1 or not math.isfinite(value) or not math.isfinite(maximum) or value < 0 or maximum < 0:
            continue
        slot = buckets[clock // step * step].setdefault(metric, {'sum': 0, 'count': 0, 'max': 0})
        slot['sum'] += value * count
        slot['count'] += count
        slot['max'] = max(slot['max'], maximum)
    points = []
    for clock, slot in buckets.items():
        point = {'clock': clock}
        for metric in ('rx', 'tx'):
            values = slot.get(metric)
            point[metric] = round(values['sum'] / values['count'], 2) if values else None
            point[metric + '_max'] = values['max'] if values else None
        points.append(point)
    return points


def history(api, device_id, name, period, now=None, device_metric=False):
    if period not in RANGES or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:\-]{0,79}', name):
        raise ValueError('Invalid history request')
    now = int(time.time()) if now is None else now
    start = now - RANGES[period]
    step = max(60, math.ceil(RANGES[period] / 300 / 60) * 60)
    hosts = api.call('host.get', {'filter': {'host': host_name(device_id)}, 'output': ['hostid']})
    if not hosts:
        return {'points': [], 'from': start, 'to': now, 'step': step, 'message': 'В Zabbix ещё нет истории устройства.'}
    keys = {'isp.device.subscribers': 'rx'} if device_metric else {item_key(name, metric): metric for metric in ('rx', 'tx')}
    items = api.call('item.get', {'hostids': [hosts[0]['hostid']], 'filter': {'key_': list(keys)}, 'output': ['itemid', 'key_']})
    item_ids = {row['itemid']: keys[row['key_']] for row in items}
    rows = []
    if item_ids:
        query = {'itemids': list(item_ids), 'time_from': start, 'time_till': now}
        if period in ('1h', '24h'):
            rows = api.call('history.get', {**query, 'history': 3 if device_metric else 0, 'output': ['itemid', 'clock', 'value'], 'sortfield': 'clock', 'sortorder': 'ASC', 'limit': 4000})
        else:
            hour = now // 3600 * 3600
            step = max(3600, math.ceil(RANGES[period] / 300 / 3600) * 3600)
            rows = api.call('trend.get', {**query, 'time_till': hour - 1, 'output': ['itemid', 'clock', 'num', 'value_avg', 'value_max'], 'limit': 2000})
            rows += api.call('history.get', {**query, 'time_from': hour, 'history': 3 if device_metric else 0, 'output': ['itemid', 'clock', 'value'], 'limit': 200})
    points = aggregate(rows, item_ids, start, now, step)
    return {'points': points, 'from': start, 'to': now, 'step': step, 'source': 'Zabbix',
            'aggregation': 'mean', 'message': None if rows else 'Данных за выбранный период пока нет.'}


if __name__ == '__main__':
    try:
        request = json.loads(sys.stdin.read(4096))
        if request.get('device_metric') not in (None, 'subscribers'):
            raise ValueError('Invalid metric')
        response = history(Zabbix.local(), int(request['device_id']), request.get('port_name', 'subscribers'), request['range'], device_metric=request.get('device_metric') == 'subscribers')
        print(json.dumps(response, ensure_ascii=False, allow_nan=False))
    except Exception:
        print(json.dumps({'error': 'Node history is unavailable'}))
        sys.exit(1)
