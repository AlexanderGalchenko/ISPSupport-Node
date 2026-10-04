#!/usr/bin/env python3
"""Read-only checks of explicitly configured devices, executed on the client node."""
import concurrent.futures
from functools import lru_cache
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def result(status, message, output=None):
    value = {"status": status, "message": message}
    if output:
        value["output"] = output[:1024]
    return value


def run(arguments, timeout, **kwargs):
    return subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, errors="replace", timeout=timeout, **kwargs)


def icmp(host):
    try:
        reply = run(["ping", "-n", "-c", "1", "-W", "2", host], 3)
        return result("ok", "Есть ответ ICMP") if reply.returncode == 0 else result("failed", "Нет ответа ICMP")
    except (OSError, subprocess.SubprocessError):
        return result("failed", "Проверка ICMP не выполнена")


@lru_cache(maxsize=1)
def huawei_module():
    spec = importlib.util.spec_from_file_location('huawei_monitor_transport', Path(__file__).with_name('huawei_collect.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ssh_profile(device):
    profile = device.get('ssh_profile')
    if profile and profile != 'auto':
        return profile
    platform = (device.get('os_name') or '').strip().lower()
    for value, keywords in [('junos', ('junos', 'juniper')), ('huawei_vrp', ('huawei', 'vrp')),
                            ('mikrotik_routeros', ('mikrotik', 'routeros')), ('cisco_ios', ('cisco', 'ios', 'nx-os'))]:
        if any(keyword in platform for keyword in keywords):
            return value
    return 'generic'


def huawei_ssh(device, host, username, port, known_hosts):
    try:
        transport = huawei_module()
        with transport.HuaweiSession(host, username, Path('/root/.ssh/id_rsa'), known_hosts,
                                     port=port, legacy_rsa=device.get('ssh_legacy_rsa') is True,
                                     session_timeout=18, command_timeout=6, connect_timeout=8,
                                     accept_new_host=True) as session:
            output = session.command('display version')
        if not re.search(r'(?i)(VRP|Huawei).*?(software|version|uptime)', output):
            return result('failed', 'SSH выполнен, но ответ display version не распознан')
        return result('ok', 'Вход по ключу, display version выполнена', output)
    except (ImportError, OSError):
        return result('failed', 'На ноде недоступен транспорт Huawei SSH / python3-pexpect')
    except Exception as error:
        message = str(error).lower()
        if 'host key' in message and 'failed' in message:
            return result('failed', 'Ключ устройства не подтверждён или изменился; проверьте fingerprint')
        if 'public key rejected' in message:
            return result('failed', 'Ключ или права пользователя отклонены')
        if 'algorithms incompatible' in message:
            return result('failed', 'Несовместимые алгоритмы SSH; проверьте профиль RSA в шаблоне')
        if 'command rejected' in message:
            return result('failed', 'SSH выполнен; display version недоступна пользователю')
        return result('failed', 'Huawei SSH не завершён: проверьте ключ, права и доступность устройства')


def ssh(device, host):
    username = device.get("ssh_username")
    if not username:
        return result("skipped", "Пользователь SSH не задан")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) or username == "root":
        return result("failed", "Недопустимый пользователь SSH")
    profile = ssh_profile(device)
    commands = {'junos': 'show version | no-more', 'cisco_ios': 'show version',
                'mikrotik_routeros': '/system resource print', 'generic': 'show version'}
    if profile not in commands and profile != 'huawei_vrp':
        return result('failed', 'Неизвестный профиль SSH в шаблоне устройства')
    port = int(device.get("ssh_port", 22))
    if not 1 <= port <= 65535:
        return result("failed", "Недопустимый порт SSH")
    state = Path("/var/lib/ispsupport-node")
    state.mkdir(parents=True, mode=0o750, exist_ok=True)
    known_hosts = state / "device_known_hosts"
    known_hosts.touch(mode=0o600, exist_ok=True)
    known_hosts.chmod(0o600)
    if profile == 'huawei_vrp':
        return huawei_ssh(device, host, username, port, known_hosts)
    command = commands[profile]
    args = ["ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=publickey", "-o", "ForwardAgent=no",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "ConnectTimeout=4", "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=3",
            "-o", "ServerAliveCountMax=1", "-p", str(port), "-l", username, host, command]
    try:
        reply = run(args, 8)
        signatures = {'junos': r'(?im)^\s*(Junos:|JUNOS\b|Model:)', 'cisco_ios': r'(?i)(Cisco|IOS|NX-OS).*?(version|software)',
                      'mikrotik_routeros': r'(?im)^\s*(version|uptime|board-name):', 'generic': r'(?i)\b(version|software)\b'}
        if reply.returncode == 0 and re.search(signatures[profile], reply.stdout):
            return result("ok", "Вход по ключу, "+command.split(' |')[0]+" выполнена", reply.stdout.strip())
        error = reply.stderr.lower()
        if "host key verification failed" in error or "host identification has changed" in error:
            return result("failed", "Изменился ключ устройства; требуется проверка fingerprint")
        if "permission denied" in error:
            return result("failed", "Ключ или права пользователя отклонены")
        if "timed out" in error or "no route to host" in error or "connection refused" in error:
            return result("failed", "SSH недоступен: проверьте маршрут, firewall и порт")
        return result("failed", "SSH или команда "+command.split(' |')[0]+" завершились ошибкой")
    except subprocess.TimeoutExpired:
        return result("failed", "Тайм-аут SSH")
    except OSError:
        return result("failed", "SSH-клиент недоступен")


def snmp(device, host):
    community = device.get("snmp_community")
    if not community:
        return result("skipped", "Community не задан")
    if not isinstance(community, str) or len(community) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in community):
        return result("failed", "Некорректный community")
    if not shutil.which("snmpget"):
        return result("failed", "На ноде требуется пакет snmp")
    port = int(device.get("snmp_port", 161))
    if not 1 <= port <= 65535:
        return result("failed", "Недопустимый порт SNMP")
    address = f"udp6:[{host}]:{port}" if ":" in host else f"udp:{host}:{port}"
    try:
        with tempfile.TemporaryDirectory(prefix="isp-snmp-") as directory:
            path = Path(directory) / "snmp.conf"
            escaped = community.replace("\\", "\\\\").replace('"', '\\"')
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write('defVersion 2c\ndefCommunity "' + escaped + '"\n')
            env = {**os.environ, "SNMPCONFPATH": directory, "MIBS": ""}
            reply = run(["snmpget", "-v", "2c", "-t", "1", "-r", "1", "-On", address,
                         ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.3.0"], 4, env=env)
            if reply.returncode == 0:
                return result("ok", "sysDescr / sysName / sysUpTime получены", reply.stdout.strip().replace(community, "[скрыто]"))
            return result("failed", "Нет корректного SNMP-ответа: проверьте community, ACL и UDP-порт")
    except (OSError, subprocess.SubprocessError):
        return result("failed", "Проверка SNMP не выполнена")


def check(device):
    try:
        host = str(ipaddress.ip_address(device["host"]))
        checks = {"id": int(device["id"]), "icmp": icmp(host), "ssh": ssh(device, host), "snmp": snmp(device, host)}
        secret = device.get("snmp_community")
        if secret:
            for protocol in ("icmp", "ssh", "snmp"):
                for key in ("output", "message"):
                    if key in checks[protocol]:
                        checks[protocol][key] = checks[protocol][key].replace(secret, "[скрыто]")[:1024 if key == "output" else 200]
        return checks
    except (ValueError, KeyError, TypeError, OSError):
        return {"id": int(device["id"]), **{key: result("failed", "Ошибка параметров проверки") for key in ("icmp", "ssh", "snmp")}}


def collect(devices):
    if len(devices) > 20:
        raise ValueError("At most 20 devices per gateway batch")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(check, devices))
