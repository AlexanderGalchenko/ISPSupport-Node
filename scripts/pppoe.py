#!/usr/bin/env python3
"""Local PPPoE profiles, systemd session control and machine-readable status."""
import argparse
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

CONFIG = Path('/etc/ispsupport-node/pppoe')
STATE = Path('/var/lib/ispsupport-node/pppoe')
ENGINE = Path(__file__).with_name('pppoe_test.py')
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')
MAC = re.compile(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
PROBE_STATES = {'HOLDING', 'HOLDING_NO_IPV4'}


def run(arguments, check=True, timeout=15):
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=timeout, check=check)


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError(f'{path}: requires a regular root-owned file with mode 600')


def name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError('Profile name: 1..32 lowercase letters, digits, underscores or dashes')
    return value


def load_profile(profile_name):
    profile_name = name(profile_name)
    path = CONFIG / (profile_name + '.json')
    private_file(path)
    profile = json.loads(path.read_text())
    if not isinstance(profile, dict) or profile.get('schema') != 1:
        raise ValueError('Profile schema must be 1')
    fields = {'schema', 'interface', 'expected_mac', 'bras_label', 'bras_address', 'bras_port',
              'device_id', 'transport_vlan', 'vlan', 'ac', 'service', 'env_file',
              'ping', 'skip_initial_tests', 'expected_ac_mac', 'note'}
    unknown = set(profile) - fields
    if unknown:
        raise ValueError('Unknown profile fields: ' + ', '.join(sorted(unknown)))
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', profile.get('interface', '')):
        raise ValueError('A dedicated interface is required')
    if not MAC.fullmatch(profile.get('expected_mac', '')):
        raise ValueError('expected_mac is required')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,60}', profile.get('bras_label', '')):
        raise ValueError('bras_label is required')
    if 'vlan' not in profile:
        raise ValueError('Set vlan to null for untagged guest Ethernet, or to an explicit VLAN ID')
    for field in ('vlan', 'transport_vlan'):
        if profile.get(field) is not None and (type(profile[field]) is not int or not 1 <= profile[field] <= 4094):
            raise ValueError(field + ' must be null or 1..4094')
    if 'bras_address' in profile:
        ipaddress.ip_address(profile['bras_address'])
    if 'device_id' in profile and (type(profile['device_id']) is not int or profile['device_id'] < 1):
        raise ValueError('device_id must be a positive integer')
    for field in ('ac', 'service', 'bras_port', 'note'):
        value = profile.get(field, '')
        if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Invalid ' + field)
    if profile.get('expected_ac_mac') and not MAC.fullmatch(profile['expected_ac_mac']):
        raise ValueError('Invalid expected_ac_mac')
    if type(profile.get('skip_initial_tests', False)) is not bool:
        raise ValueError('skip_initial_tests must be boolean')
    if 'ping' in profile:
        targets = profile['ping']
        if not isinstance(targets, list) or not 1 <= len(targets) <= 5:
            raise ValueError('ping must contain 1..5 IPv4 addresses')
        for target in targets:
            if not isinstance(target, str):
                raise ValueError('Invalid ping target')
            ipaddress.IPv4Address(target)
    env_path = Path(profile.get('env_file', str(CONFIG / (profile_name + '.env'))))
    if not env_path.is_absolute() or env_path.parent != CONFIG or env_path.suffix != '.env':
        raise ValueError('env_file must be an absolute .env path directly inside ' + str(CONFIG))
    profile['env_file'] = str(env_path)
    return profile


def binding(profile):
    return {k: v for k, v in profile.items() if k != 'env_file'}


def arguments(profile_name, profile, check=False, output=None):
    args = [str(ENGINE), '--interface', profile['interface'], '--bras', profile['bras_label'],
            '--expect-mac', profile['expected_mac'], '--env-file', profile['env_file'],
            '--namespace', 'isp-pppoe-' + name(profile_name)]
    args += ['--untagged'] if profile['vlan'] is None else ['--vlan', str(profile['vlan'])]
    for field in ('ac', 'service'):
        if profile.get(field):
            args += ['--' + field, profile[field]]
    if profile.get('ping'):
        args += ['--ping', *profile['ping']]
    if check:
        args += ['--check']
    else:
        args += ['--run', '--hold', '--output', str(output)]
        if profile.get('skip_initial_tests', False):
            args += ['--skip-initial-tests']
    return args


def atomic_json(path, data):
    temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    try:
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def unit(profile_name, suffix='service'):
    return 'ispsupport-pppoe@' + name(profile_name) + '.' + suffix


def timer(profile_name):
    return 'ispsupport-pppoe-probe@' + name(profile_name) + '.timer'


def system_state(unit_name):
    reply = run(['systemctl', 'show', unit_name, '--property=ActiveState,SubState,MainPID,Result'], check=False)
    if reply.returncode:
        raise RuntimeError('Cannot read systemd state: ' + reply.stderr.strip())
    return dict(line.split('=', 1) for line in reply.stdout.splitlines() if '=' in line)


def read_current(profile_name):
    root = STATE / name(profile_name)
    path = root / 'current.json'
    if not path.exists():
        return None, None
    current = json.loads(path.read_text())
    run_id = current.get('run_id', '')
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}', run_id):
        raise ValueError('Invalid current run reference')
    report = root / 'runs' / run_id / 'result.json'
    return current, json.loads(report.read_text()) if report.exists() else None


def status(profile_name):
    profile = load_profile(profile_name)
    current, report = read_current(profile_name)
    service = system_state(unit(profile_name))
    active = service.get('ActiveState') == 'active'
    # Read the PID from systemd, never signal a PID from a report on disk.
    value = {'profile': profile_name, 'binding': binding(profile), 'service': service,
             'timer': system_state(timer(profile_name)), 'active': active,
             'current': current, 'session': report, 'connected': False}
    if report and active:
        timestamp = report.get('updated_utc') or report.get('checks_started_utc') or report.get('connected_utc')
        if timestamp:
            import calendar
            age = max(0, time.time() - calendar.timegm(time.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')))
            value['report_age_seconds'] = round(age, 1)
            # A bounded check round can take several minutes on a broken path.
            value['connected'] = (report.get('ipv4_available') is True and
                                  report.get('status') in PROBE_STATES | {'TESTING', 'CONNECTED'} and age < 300)
    expected = (current or {}).get('binding', profile).get('expected_ac_mac')
    observed = (report or {}).get('observed_ac_mac')
    value['ac_mac_matches'] = expected.lower() == observed.lower() if expected and observed else None
    return value


def start_session(profile_name, profile):
    private_file(Path(profile['env_file']))
    lock = open('/run/lock/ispsupport-pppoe-' + name(profile_name) + '.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    root = STATE / name(profile_name)
    runs = root / 'runs'
    runs.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_id = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:10]
    output = runs / run_id
    try:
        code_revision = run(['git', '-C', str(ENGINE.parent.parent), 'rev-parse', 'HEAD']).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        code_revision = None
    current = {'run_id': run_id, 'binding': binding(profile), 'code_revision': code_revision,
               'report': str(output / 'result.json'), 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    atomic_json(root / 'current.json', current)
    atomic_json(runs / (run_id + '.json'), current)
    spec = importlib.util.spec_from_file_location('pppoe_session', ENGINE)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    old_argv = sys.argv
    sys.argv = arguments(profile_name, profile, output=output)
    try:
        result = engine.main()
    finally:
        sys.argv = old_argv
    current['exit_code'] = result
    current['finished_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    if output.exists():
        atomic_json(output / 'binding.json', current)
    atomic_json(root / 'current.json', current)
    atomic_json(runs / (run_id + '.json'), current)
    return result


def probe(profile_name):
    value = status(profile_name)
    # A timer must neither start/reconnect a session nor kill a starting process.
    if not value['active'] or not value['session'] or value['session'].get('status') not in PROBE_STATES:
        print(json.dumps({'profile': profile_name, 'probe': 'skipped', 'reason': 'session not ready or test already running'}))
        return 0
    run(['systemctl', 'kill', '--kill-who=main', '--signal=USR1', unit(profile_name)])
    print(json.dumps({'profile': profile_name, 'probe': 'requested'}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['list', 'check', 'run', 'start', 'stop', 'status', 'probe', 'schedule', 'quiet'])
    parser.add_argument('profile', nargs='?')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if os.geteuid() != 0:
            raise ValueError('Run as root')
        if args.action == 'list':
            print(json.dumps([{'profile': p.stem, 'binding': binding(load_profile(p.stem))}
                              for p in sorted(CONFIG.glob('*.json'))], ensure_ascii=False, indent=2))
            return 0
        profile_name = name(args.profile)
        # Stop/quiet remain available even if a profile is missing or damaged.
        if args.action == 'stop':
            timer_result = run(['systemctl', 'disable', '--now', timer(profile_name)], check=False, timeout=30)
            run(['systemctl', 'stop', unit(profile_name)], timeout=190)
            if timer_result.returncode:
                print(timer_result.stderr, file=sys.stderr)
            return 0
        if args.action == 'quiet':
            run(['systemctl', 'disable', '--now', timer(profile_name)], timeout=30)
            return 0
        profile = load_profile(profile_name)
        if args.action == 'status':
            print(json.dumps(status(profile_name), ensure_ascii=False, indent=2))
            return 0
        if args.action == 'probe':
            return probe(profile_name)
        if args.action == 'schedule':
            run(['systemctl', 'enable', '--now', timer(profile_name)], timeout=30)
            return 0
        if args.action == 'start':
            private_file(Path(profile['env_file']))
            run(['systemctl', 'start', unit(profile_name)], timeout=30)
            return 0
        if args.action == 'check':
            private_file(Path(profile['env_file']))
            return subprocess.call([sys.executable, *arguments(profile_name, profile, check=True)])
        return start_session(profile_name, profile)
    except (ValueError, TypeError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('PPPOE ERROR: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
