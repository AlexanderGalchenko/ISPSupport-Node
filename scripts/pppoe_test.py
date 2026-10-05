#!/usr/bin/env python3
"""ISP Support: isolated IPv4 PPPoE test/session (Linux, Python >= 3.8).

Debian/Ubuntu packages: python3 iproute2 ppp iputils-ping curl dnsutils procps
Kernel support: modprobe pppoe (requires kmod; creates /dev/ppp via ppp_generic).
Read-only check:
  sudo python3 pppoe_test.py --interface eth1 --check
Untagged Ethernet as seen INSIDE this VM (a hypervisor tag is not a guest tag):
  sudo python3 pppoe_test.py --interface eth1 --bras lab --untagged --run
Guest VLAN, only if tagged frames actually arrive on eth1:
  sudo python3 pppoe_test.py --interface eth1 --bras lab --vlan 123 --run
Optional: --service NAME --ac NAME --expect-mac 02:00:00:00:00:01
Hold the session after one round of checks, until explicitly stopped:
  sudo python3 pppoe_test.py --untagged --run --hold --namespace isp-pppoe-lab
--skip-initial-tests with --hold starts without ping/DNS/HTTP probes.
In hold mode, SIGUSR1 requests one more round of checks. SIGTERM stops it.
Use a transient systemd service to survive SSH disconnects; see the runbook.

The dedicated NIC is temporarily moved, retaining its MAC. No veth, NAT or
connection to the host namespace is created. Only IPv4 PPP is tested. The
script refuses addressed, routed, managed, enslaved, or parent interfaces.
Private /etc/ppp, resolv.conf and nsswitch.conf are bound by ip netns exec;
existing PPP options/hooks and the host DNS resolver are not used.
Credentials are read from .env beside this script by default:
  PPPOE_USERNAME=your-login
  PPPOE_PASSWORD=your-password
Use --env-file /path/to/bras.env to choose another file. File credentials
take precedence over environment variables. If the default .env is absent,
the environment or interactive prompt can still be used. An explicit missing
--env-file is an error. Both keys are required in a file. Values are literal;
optional enclosing single/double quotes are stripped, without expansion or
escape processing. Credentials are never passed to child commands in their
arguments or environment. Store the credential file with mode 600.
There is one connection attempt, with bounded commands and no reconnect.
Hold mode disables client idle/maxconnect limits. LCP keepalives remain active.
The BRAS can still disconnect the subscriber, including via RADIUS policy.
INT/TERM/HUP trigger cleanup. SIGKILL/power loss cannot run cleanup: recovery
instructions and an interface snapshot are saved before moving the NIC.

--bras is an EXPECTED inventory label, not proof of the responding BRAS.
Use pppoe.py and a local profile for managed node bindings and systemd control.

Exit codes: 0 all checks pass or hold stopped by operator; 1 degraded service;
2 setup/session failure;
3 cleanup/state verification failure; 130 interrupted. JSON contains no
credentials; the private pppd.log may contain the subscriber login.
"""
import argparse
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit


ENV = dict(os.environ, LC_ALL="C", LANG="C", SYSTEMD_COLORS="0",
           SYSTEMD_PAGER="cat")
VERSION = "3.2"
for _credential_key in ("PPPOE_USERNAME", "PPPOE_PASSWORD"):
    ENV.pop(_credential_key, None)


def command(args, timeout=12, check=True):
    try:
        p = subprocess.run([str(x) for x in args], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, env=ENV)
        code, output = p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        raw = e.stdout or b""
        output = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        code, output = 124, output + "\nCOMMAND TIMEOUT"
    if check and code:
        raise RuntimeError("{}: {}".format(" ".join(map(str, args)), output.strip()))
    return code, output


def ipjson(*args):
    return json.loads(command(["ip", "-j", *args])[1])


def save(path, data):
    # Status readers must never see half a JSON document.
    path = Path(path)
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def quote_option(value):
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("PPP values must not contain control characters")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def read_dotenv(path, required=False):
    """Read literal credential values; never execute/source shell content."""
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        if required:
            raise RuntimeError("Credential file not found: " + str(path))
        return None
    values = {}
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match:
            raise RuntimeError("Invalid .env assignment on line " + str(number))
        key, raw = match.groups()
        if key not in ("PPPOE_USERNAME", "PPPOE_PASSWORD"):
            continue
        if key in values:
            raise RuntimeError("Duplicate .env key on line " + str(number))
        if raw[:1] in ("'", '"'):
            quoted = re.fullmatch(r"(['\"])(.*?)\1(?:\s+#.*)?\s*", raw)
            if not quoted:
                raise RuntimeError("Invalid .env quotes on line " + str(number))
            value = quoted.group(2)
        else:
            value = re.split(r"\s+#", raw, maxsplit=1)[0].rstrip()
        quote_option(value)
        values[key] = value
    if not values.get("PPPOE_USERNAME") or not values.get("PPPOE_PASSWORD"):
        raise RuntimeError("The .env file must contain nonempty PPPOE_USERNAME and PPPOE_PASSWORD")
    return values


def credentials(file_values=None):
    username = os.environ.pop("PPPOE_USERNAME", None)
    password = os.environ.pop("PPPOE_PASSWORD", None)
    if file_values is not None:
        return file_values["PPPOE_USERNAME"], file_values["PPPOE_PASSWORD"]
    if username is not None or password is not None:
        if not username or not password:
            raise RuntimeError("Set both PPPOE_USERNAME and PPPOE_PASSWORD to nonempty values")
        return username, password
    if not sys.stdin.isatty():
        raise RuntimeError("Use a .env file, terminal, or both PPPOE_USERNAME and PPPOE_PASSWORD environment variables")
    return input("PPPoE login: ").strip(), getpass.getpass("PPPoE password: ")


def host_state(ignore_linklocal_iface=None):
    # Local/link-local routes change when the dedicated NIC moves. Compare
    # all other tables and policy rules, not just the main default route.
    def canonical(items):
        volatile = {"expires", "age", "used", "lastuse", "cache"}
        def clean(x):
            if isinstance(x, dict):
                return {k: clean(v) for k, v in x.items() if k not in volatile}
            if isinstance(x, list):
                return [clean(v) for v in x]
            return x
        return sorted((clean(x) for x in items), key=lambda x: json.dumps(x, sort_keys=True))
    routes6 = ipjson("-6", "route", "show", "table", "all")
    routes6 = [r for r in routes6 if not (r.get("dev") == ignore_linklocal_iface and
               str(r.get("dst", "")).startswith(("fe80:", "ff00:")))]
    return {"routes4": canonical(ipjson("-4", "route", "show", "table", "all")),
            "routes6": canonical(routes6),
            "rules4": canonical(ipjson("-4", "rule", "show")),
            "rules6": canonical(ipjson("-6", "rule", "show")),
            "resolv_sha256": hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest()}


def preflight(a):
    if os.geteuid() != 0:
        raise RuntimeError("Run as root (sudo).")
    required = ("ip", "pppd", "ping", "curl", "dig", "stat", "sysctl")
    if getattr(a, "capture_control", False):
        required += ("tcpdump", "timeout")
    missing = [x for x in required if not shutil.which(x)]
    if missing:
        raise RuntimeError("Missing commands: " + ", ".join(missing) +
                           ". Debian/Ubuntu: apt-get install python3 iproute2 ppp iputils-ping curl dnsutils procps")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", a.interface):
        raise RuntimeError("Invalid interface name")
    link = ipjson("-d", "link", "show", "dev", a.interface)[0]
    addresses = ipjson("address", "show", "dev", a.interface)[0]["addr_info"]
    if link.get("link_type") != "ether" or link.get("linkinfo", {}).get("info_kind"):
        raise RuntimeError("Use a dedicated Ethernet NIC, not a bridge/bond/VLAN/virtual child")
    if link.get("master") or "SLAVE" in link.get("flags", []):
        raise RuntimeError("Interface belongs to a master (bridge/bond/VRF)")
    if list(Path("/sys/class/net", a.interface).glob("upper_*")):
        raise RuntimeError("Interface has child/upper devices")
    for addr in addresses:
        if addr["family"] != "inet6" or addr.get("scope") != "link":
            raise RuntimeError("Interface has an IP address other than IPv6 link-local")
    routes4 = ipjson("-4", "route", "show", "table", "all", "dev", a.interface)
    routes6 = ipjson("-6", "route", "show", "table", "all", "dev", a.interface)
    if routes4 or any(not str(r.get("dst", "")).startswith(("fe80:", "ff00:")) for r in routes6):
        raise RuntimeError("Interface is used by IP routes")
    for family in ("-4", "-6"):
        for rule in ipjson(family, "rule", "show"):
            if a.interface in (rule.get("iif"), rule.get("oif"), rule.get("iifname"), rule.get("oifname")):
                raise RuntimeError("Interface is referenced by a policy-routing rule")
    if a.expect_mac and link["address"].lower() != a.expect_mac.lower():
        raise RuntimeError("MAC does not match --expect-mac")
    if "LOWER_UP" not in link.get("flags", []):
        raise RuntimeError("No carrier (LOWER_UP) on the dedicated interface")
    if shutil.which("nmcli"):
        rc, text = command(["nmcli", "-g", "GENERAL.STATE", "device", "show", a.interface], check=False)
        if rc == 0 and not text.strip().startswith("10 "):
            raise RuntimeError("NetworkManager manages the NIC; dedicate/unmanage it before testing")
    if shutil.which("networkctl"):
        rc, text = command(["networkctl", "status", "--no-pager", "--", a.interface], check=False)
        match = re.search(r"Network File:\s*(\S+)", text)
        if rc == 0 and match and match.group(1) not in ("n/a", "-"):
            raise RuntimeError("systemd-networkd manages this NIC: " + match.group(1))
    # ifupdown may bring a moved NIC up again via hotplug rules.
    state = Path("/run/network/ifstate")
    if state.exists() and any(line.startswith(a.interface + "=") for line in state.read_text().splitlines()):
        raise RuntimeError("ifupdown has an active configuration for this NIC")
    ppprc = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".ppprc"
    if ppprc.exists() or ppprc.is_symlink():
        raise RuntimeError("A user .ppprc exists; refusing inherited PPP configuration")
    if not Path("/etc/ppp").is_dir() or not Path("/etc/nsswitch.conf").is_file():
        raise RuntimeError("Expected /etc/ppp and /etc/nsswitch.conf (standard Debian/Ubuntu)")
    if not Path("/dev/ppp").is_char_device():
        raise RuntimeError("Kernel PPP device /dev/ppp is absent. On the node run: modprobe pppoe")
    # Locate only the plugin belonging to the installed pppd ABI.
    version = command(["pppd", "--version"])[1].strip()
    m = re.search(r"\b(2\.[45]\.\d+)\b", version)
    if not m:
        raise RuntimeError("Supported pppd versions: 2.4.x / 2.5.x; found " + version)
    candidates = []
    for base in (Path("/usr/lib"), Path("/usr/lib64"), Path("/lib")):
        for pattern in ("pppd/" + m.group(1) + "/*pppoe.so",
                        "*/pppd/" + m.group(1) + "/*pppoe.so"):
            candidates.extend(base.glob(pattern))
    plugins = sorted({str(p.resolve()) for p in candidates})
    if not plugins:
        raise RuntimeError("No PPPoE plugin matching " + version)
    sysctls = {}
    for family in ("ipv4", "ipv6"):
        for p in Path("/proc/sys/net", family, "conf", a.interface).glob("*"):
            try:
                value = p.read_text().strip()
                if re.fullmatch(r"-?\d+", value):
                    sysctls[str(p)] = value
            except OSError:
                pass
    return {"link": link, "addresses": addresses, "sysctls": sysctls,
            "pppd": version, "plugin": plugins[0]}


def control_filter(mac):
    """Capture only our PPP control traffic, excluding PAP requests and CHAP proofs."""
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise ValueError("Invalid capture MAC")
    def payload(ethertype, protocol):
        code = protocol + 2
        controls = " or ".join("ether[{}:2] = {}".format(protocol, value)
                               for value in ("0xc021", "0x8021", "0x8057"))
        # Authentication results only: PAP Ack/Nak and CHAP Success/Failure.
        auth = ("(ether[{p}:2] = 0xc023 and (ether[{c}] = 2 or ether[{c}] = 3)) or "
                "(ether[{p}:2] = 0xc223 and (ether[{c}] = 3 or ether[{c}] = 4))").format(p=protocol, c=code)
        return "(ether[{e}:2] = 0x8863 or (ether[{e}:2] = 0x8864 and ({p} or {a})))".format(e=ethertype, p=controls, a=auth)
    return "ether host {} and ({} or ((ether[12:2] = 0x8100 or ether[12:2] = 0x88a8) and {}))".format(
        mac, payload(12, 20), payload(16, 24))


class Test:
    def __init__(self, a, before):
        self.a, self.before = a, before
        token = uuid.uuid4().hex[:10]
        self.ns, self.ppp = a.namespace or "isp-test-" + token, "bt" + token
        self.etc = Path("/etc/netns") / self.ns
        self.out = Path(a.output or ("bras-test-" + a.bras + "-" +
                        time.strftime("%Y%m%d-%H%M%S") + "-" + token)).resolve()
        self.created, self.moved, self.proc = False, False, None
        self.capture = None
        self.out_created, self.etc_created = False, False
        self.connected_monotonic = None
        self.probe_requested = False
        self.hook_offset, self.probe_number = 0, 0
        self.report = {"schema": 1, "expected_bras_label": a.bras,
                       "script_version": VERSION, "mode": "hold" if a.hold else "test",
                       "identity_verified": False, "interface": a.interface,
                       "mac": before["link"]["address"], "vlan": a.vlan,
                       "service_filter": a.service, "ac_filter": a.ac,
                       "namespace": self.ns, "pppd_version": before["pppd"],
                       "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "checks": {}, "status": "STARTED"}

    def event(self, kind, **fields):
        row = {"at_utc": utcnow(), "event": kind, **fields}
        if self.out_created:
            with (self.out / "events.jsonl").open("a") as log:
                log.write(json.dumps(row, ensure_ascii=False) + "\n")
        print("EVENT " + json.dumps(row, ensure_ascii=False), flush=True)

    def read_hook_events(self):
        """Copy IPCP hook events, including flaps shorter than our poll interval."""
        path = self.etc / "ppp/link-events.jsonl"
        if not path.exists():
            return False
        got_up = False
        with path.open() as stream:
            stream.seek(self.hook_offset)
            while True:
                line = stream.readline()
                if not line or not line.endswith("\n"):
                    break
                row = json.loads(line)
                self.hook_offset = stream.tell()
                kind = row.pop("event")
                self.event(kind, **row)
                self.report["last_ipcp_event"] = {"event": kind, **row}
                counter = "ipcp_up_events" if kind == "IPCP_UP" else "ipcp_down_events"
                self.report[counter] = self.report.get(counter, 0) + 1
                got_up |= kind == "IPCP_UP"
        return got_up

    def address(self):
        rc, raw = command(["ip", "-n", self.ns, "-j", "-4", "address", "show", "dev", self.ppp], check=False)
        if rc == 0:
            rows = json.loads(raw)
            if rows and "UP" in rows[0].get("flags", []) and rows[0].get("addr_info"):
                return rows[0]
        return None

    def nscommand(self, args, **kwargs):
        return command(["ip", "netns", "exec", self.ns, *args], **kwargs)

    def check(self, name, args, timeout=15):
        rc, text = self.nscommand(args, timeout=timeout, check=False)
        result = {"exit_code": rc, "output": text.strip(), "ok": rc == 0}
        self.report["checks"][name] = result
        print("{} (exit={})\n{}".format(name, rc, text.strip()), flush=True)
        return result

    def start_capture(self, nic):
        logpath = self.out / "control-capture.log"
        pcap = self.out / "ppp-control.pcap"
        packet_filter = control_filter(self.before["link"]["address"])
        self.report["control_capture"] = {"pcap": str(pcap), "log": str(logpath),
                                          "max_seconds": 75, "max_packets": 1000,
                                          "filter": packet_filter}
        with logpath.open("w") as log:
            self.capture = subprocess.Popen(["ip", "netns", "exec", self.ns,
                "timeout", "--signal=INT", "--kill-after=3", "75", "tcpdump",
                "-Z", "root", "-n", "-p", "-U", "-s", "2048", "-c", "1000",
                "-i", nic, "-w", str(pcap), packet_filter], stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, env=ENV, start_new_session=True)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if self.capture.poll() is not None:
                raise RuntimeError("Control capture exited; inspect control-capture.log")
            if "listening on " in logpath.read_text(errors="replace"):
                self.event("CONTROL_CAPTURE_READY", interface=nic, max_seconds=75)
                save(self.out / "result.json", self.report)
                return
            time.sleep(0.05)
        raise RuntimeError("Control capture did not become ready; PPP was not started")

    def stop_capture(self):
        if self.capture is None:
            return
        if self.capture.poll() is None:
            self.capture.send_signal(signal.SIGINT)
            try:
                self.capture.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Only this capture's own session/process group, never other netns processes.
                os.killpg(self.capture.pid, signal.SIGKILL)
                self.capture.wait(timeout=3)
        self.report["control_capture"]["process_exit_code"] = self.capture.returncode

    def prepare(self, username, password):
        if self.etc.exists() or self.etc.is_symlink() or os.path.lexists("/run/netns/" + self.ns):
            raise RuntimeError("Namespace or private configuration already exists: " + self.ns)
        self.out.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.out_created = True
        save(self.out / "interface-before.json", self.before)
        self.host_before = host_state(self.a.interface)
        save(self.out / "host-before.json", self.host_before)
        recovery = """Only if the process was killed and normal cleanup did not finish:
1. Inspect: ip netns pids {ns}
2. Terminate ONLY the listed test processes: kill -TERM <listed-PIDs>
   Then repeat step 1 and wait for them to exit.
3. If the NIC is still there: ip -n {ns} link set {nic} netns 1
4. Restore original state: ip link set {nic} {up}
5. After no processes remain and the NIC has returned: ip netns del {ns}
6. Remove the private credential directory: rm -rf -- {etc}
Compare interface-before.json / host-before.json with the restored state.
PID 1 must be in the node's original network namespace for step 3.
""".format(ns=self.ns, nic=self.a.interface, up="up" if "UP" in self.before["link"]["flags"] else "down", etc=self.etc)
        (self.out / "RECOVERY.txt").write_text(recovery)
        save(self.out / "result.json", self.report)
        self.etc.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.etc_created = True
        (self.etc / "ppp").mkdir(mode=0o700)
        (self.etc / "resolv.conf").write_text("nameserver 192.0.2.1\noptions timeout:2 attempts:1\n")
        nss = Path("/etc/nsswitch.conf").read_text()
        nss = re.sub(r"(?m)^hosts:.*$", "hosts: dns", nss)
        if not re.search(r"(?m)^hosts:", nss):
            nss += "\nhosts: dns\n"
        (self.etc / "nsswitch.conf").write_text(nss)
        # Stock hooks are hidden entirely, not merely overridden by a later option.
        for hookname, event in (("ip-up", "IPCP_UP"), ("ip-down", "IPCP_DOWN")):
            hook = ("#!{python}\nimport os,json,time\n"
                    "keys={keys}\n"
                    "peer={{k:os.environ.get(k) for k in keys}}\n"
                    "if {up}:\n"
                    "    with open('/etc/ppp/peer.json.tmp','w') as f: json.dump(peer,f)\n"
                    "    os.replace('/etc/ppp/peer.json.tmp','/etc/ppp/peer.json')\n"
                    "row={{'at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'event':{event},'peer':peer}}\n"
                    "with open('/etc/ppp/link-events.jsonl','a') as f: f.write(json.dumps(row)+'\\n')\n"
                    ).format(python=sys.executable, keys=repr(["IFNAME", "IPLOCAL", "IPREMOTE", "DNS1", "DNS2", "MACREMOTE", "ACNAME"]),
                             up=repr(hookname == "ip-up"), event=repr(event))
            (self.etc / "ppp" / hookname).write_text(hook)
            (self.etc / "ppp" / hookname).chmod(0o700)
        for filename in ("pap-secrets", "chap-secrets"):
            (self.etc / "ppp" / filename).write_text("")
        nic = "testvlan" if self.a.vlan else self.a.interface
        options = ["plugin " + quote_option(self.before["plugin"]), "nic-" + nic,
                   "user " + quote_option(username), "password " + quote_option(password),
                   "ifname " + self.ppp, "linkname " + self.ns,
                   "nodetach", "noauth", "noipdefault", "noipv6", "hide-password",
                   "nodefaultroute", "usepeerdns", "mtu 1492", "mru 1492",
                   "nopersist", "maxfail 1", "maxconnect " + ("0" if self.a.hold else "180"),
                   "idle 0", "noproxyarp",
                   "noccp", "novj", "lcp-echo-interval 10", "lcp-echo-failure 3",
                   "logfd 1"]
        # These legacy names are accepted in 2.4.x and 2.5.x.
        if self.a.service:
            options.append("rp_pppoe_service " + quote_option(self.a.service))
        if self.a.ac:
            options.append("rp_pppoe_ac " + quote_option(self.a.ac))
        (self.etc / "ppp/options").write_text("\n".join(options) + "\n")
        command(["ip", "netns", "add", self.ns])
        self.created = True
        # Verify each bind mount BEFORE moving the NIC or running pppd.
        for name in ("ppp", "resolv.conf", "nsswitch.conf"):
            expected = command(["stat", "-Lc", "%d:%i", self.etc / name])[1].strip()
            actual = self.nscommand(["stat", "-Lc", "%d:%i", "/etc/" + name])[1].strip()
            if actual != expected:
                raise RuntimeError("Private /etc/{} bind mount failed".format(name))
        # Set the intent before the syscall; cleanup checks actual placement.
        self.moved = True
        command(["ip", "link", "set", self.a.interface, "netns", self.ns])
        command(["ip", "-n", self.ns, "link", "set", "lo", "up"])
        # IPv6 is out of scope; suppress SLAAC on the Ethernet transport.
        self.nscommand(["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1",
                        "net.ipv6.conf.default.disable_ipv6=1"])
        command(["ip", "-n", self.ns, "link", "set", self.a.interface, "up"])
        if self.a.vlan:
            command(["ip", "-n", self.ns, "link", "add", "link", self.a.interface,
                     "name", nic, "type", "vlan", "id", self.a.vlan])
            command(["ip", "-n", self.ns, "link", "set", nic, "up"])
        if getattr(self.a, "capture_control", False):
            self.start_capture(nic)
        log = open(self.out / "pppd.log", "w")
        try:
            self.proc = subprocess.Popen(["ip", "netns", "exec", self.ns, "pppd"],
                                         stdin=subprocess.DEVNULL, stdout=log,
                                         stderr=subprocess.STDOUT, env=ENV,
                                         start_new_session=True)
        finally:
            log.close()

    def connect(self):
        print("Waiting for PPPoE/IPCP (up to 60 s)...", flush=True)
        deadline, address = time.monotonic() + 60, None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.report["pppd_exit_code"] = self.proc.returncode
                raise RuntimeError("pppd exited; inspect the private pppd.log")
            address = self.address()
            if address:
                break
            time.sleep(0.5)
        if not address:
            raise RuntimeError("PPPoE/IPCP did not reach IPv4 UP in 60 s; inspect pppd.log")
        self.connected_monotonic = time.monotonic()
        self.report["connected_utc"] = utcnow()
        self.report["ipv4_available"] = True
        self.report["ppp_interface"] = address
        print("[OK] PPP IPv4: " + address["addr_info"][0]["local"], flush=True)
        command(["ip", "-n", self.ns, "route", "add", "default", "dev", self.ppp])
        self.report["test_routes"] = json.loads(command(["ip", "-n", self.ns, "-j", "-4", "route", "show"])[1])
        peerfile = self.etc / "ppp/peer.json"
        for _ in range(20):
            try:
                self.report["peer"] = json.loads(peerfile.read_text())
                break
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.1)
        self.configure_dns()
        self.read_hook_events()
        self.log_summary()
        self.event("CONNECTED", namespace=self.ns, ppp_interface=self.ppp,
                   local_ip=address["addr_info"][0]["local"],
                   ac_mac=self.report.get("observed_ac_mac"),
                   pppoe_session_id=self.report.get("pppoe_session_id"))
        self.report["status"] = "CONNECTED"
        save(self.out / "result.json", self.report)

    def configure_dns(self):
        try:
            self.report["peer"] = json.loads((self.etc / "ppp/peer.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        peer_dns = []
        for key in ("DNS1", "DNS2"):
            value = self.report.get("peer", {}).get(key)
            try:
                ip = ipaddress.IPv4Address(value)
                if not (ip.is_unspecified or ip.is_loopback or ip.is_multicast):
                    peer_dns.append(str(ip))
            except (ValueError, TypeError):
                pass
        servers = list(dict.fromkeys(peer_dns or ["77.88.8.8", "8.8.8.8"]))
        self.report["dns_source"] = "peer" if peer_dns else "public_fallback"
        if not peer_dns:
            print("[WARN] BRAS supplied no usable DNS: checking explicit public resolvers", flush=True)
        # Rewrite in place: ip netns exec will bind this file for every command.
        (self.etc / "resolv.conf").write_text("".join("nameserver " + ip + "\n" for ip in servers) +
                                             "options timeout:2 attempts:1\n")
        self.report["dns_servers"] = servers
        return servers

    def exercise(self):
        if self.connected_monotonic is None:
            self.connect()
        self.report["checks"] = {}
        address = self.address()
        if not address:
            raise RuntimeError("PPP has no active IPv4 interface for tests")
        self.report["checks_started_utc"] = utcnow()
        for target in self.a.ping:
            result = self.check("ping_" + target,
                                ["ping", "-4", "-n", "-I", self.ppp, "-c", "5", "-W", "2", "-w", "12", target])
            loss = re.search(r"([\d.]+)% packet loss", result["output"])
            result["loss_percent"] = float(loss.group(1)) if loss else None
            rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", result["output"])
            if rtt:
                result["rtt_ms"] = dict(zip(("min", "avg", "max", "mdev"), map(float, rtt.groups())))
            result["ok"] = result["ok"] and result["loss_percent"] == 0
        servers = self.configure_dns()
        for server in servers:
            r = self.check("dns_" + server, ["dig", "@" + server, "www.yandex.ru", "A",
                                            "+time=3", "+tries=1", "+noall", "+comments", "+answer"])
            r["ok"] = r["ok"] and "status: NOERROR" in r["output"] and bool(re.search(r"\sA\s+(\d+\.){3}\d+", r["output"]))
        self.https_test(servers)
        mtu = address["mtu"]
        # DF payload excludes the 20-byte IPv4 and 8-byte ICMP headers.
        self.check("mtu_df_" + str(mtu), ["ping", "-4", "-n", "-I", self.ppp, "-M", "do",
                   "-s", str(mtu - 28), "-c", "3", "-W", "2", "-w", "8", self.a.ping[0]], timeout=10)
        self.report["pppd_alive_after_checks"] = self.proc.poll() is None
        good = all(r["ok"] for r in self.report["checks"].values())
        self.report["checks_finished_utc"] = utcnow()
        self.report["status"] = "PASS" if good and self.report["dns_source"] == "peer" and self.report["pppd_alive_after_checks"] else "DEGRADED"
        return 0 if self.report["status"] == "PASS" else 1

    def hold_probe(self):
        self.probe_requested = False
        self.probe_number += 1
        self.report["status"] = "TESTING"
        save(self.out / "result.json", self.report)
        self.event("TEST_STARTED", number=self.probe_number)
        try:
            rc = self.exercise()
            summary = {"number": self.probe_number, "status": self.report["status"], "exit_code": rc,
                       "finished_utc": utcnow(), "checks": self.report["checks"]}
        except Exception as e:
            summary = {"number": self.probe_number, "status": "ERROR", "error": str(e),
                       "finished_utc": utcnow(), "checks": self.report["checks"]}
        path = self.out / ("probe-{:04d}.json".format(self.probe_number))
        save(path, summary)
        self.report["last_test"] = {k: v for k, v in summary.items() if k != "checks"}
        self.report["last_test"]["report"] = str(path)
        self.event("TEST_FINISHED", **self.report["last_test"])

    def hold(self):
        self.connect()
        if not self.a.skip_initial_tests or self.probe_requested:
            self.hold_probe()
        self.event("HOLD_STARTED", message="No periodic traffic tests. SIGUSR1: one test round; SIGTERM: stop. LCP keepalives remain active.")
        previous = None
        while True:
            got_up = self.read_hook_events()
            code = self.proc.poll()
            if code is not None:
                self.report.update(status="SESSION_DOWN", pppd_exit_code=code,
                                   ipv4_available=False, disconnected_utc=utcnow())
                self.event("SESSION_DOWN", pppd_exit_code=code, reconnect=False)
                return 2
            address = self.address()
            signature = tuple((a["local"], a.get("peer"), a["prefixlen"])
                              for a in address["addr_info"]) if address else ()
            if got_up and address:
                # IPCP can renegotiate without a new pppd process. Repair only
                # this namespace's default route and refresh peer DNS.
                command(["ip", "-n", self.ns, "route", "replace", "default", "dev", self.ppp])
                self.configure_dns()
            if signature != previous:
                self.event("IPV4_STATE", available=bool(address), addresses=signature)
                previous = signature
            self.report.update(status="HOLDING" if address else "HOLDING_NO_IPV4",
                               ipv4_available=bool(address), current_ppp_interface=address,
                               since_first_ipv4_seconds=round(time.monotonic() - self.connected_monotonic, 1),
                               updated_utc=utcnow())
            self.log_summary()
            save(self.out / "result.json", self.report)
            if self.probe_requested:
                self.hold_probe()
                continue
            time.sleep(5)

    def https_test(self, servers):
        # Resolve EVERY redirect explicitly inside the namespace. --resolve
        # also avoids a host nscd socket/cache on systems running nscd.
        web = {"ok": False, "hops": []}
        self.report["checks"]["https_yandex"] = web
        url = "https://www.yandex.ru/"
        for hop in range(5):
            u = urlsplit(url)
            if u.scheme != "https" or not u.hostname or u.username or u.password:
                web["error"] = "Refused a redirect outside HTTPS or with userinfo"
                return
            host, port = u.hostname.encode("idna").decode(), u.port or 443
            address = None
            for server in servers:
                rc, raw = self.nscommand(["dig", "@" + server, "-q", host, "-t", "A", "+short",
                                          "+time=2", "+tries=1"], check=False, timeout=4)
                if rc == 0:
                    for line in raw.splitlines():
                        try:
                            ip = ipaddress.IPv4Address(line.strip())
                            if not (ip.is_loopback or ip.is_unspecified or ip.is_multicast):
                                address = str(ip)
                                break
                        except ValueError:
                            pass
                if address:
                    break
            if not address:
                web["error"] = "No IPv4 DNS answer for " + host
                return
            rc, output = self.nscommand(["curl", "-q", "-4", "--noproxy", "*", "--interface", self.ppp,
                "--resolve", "{}:{}:{}".format(host, port, address),
                "--connect-timeout", "8", "--max-time", "20", "--max-filesize", "5242880",
                "--proto", "=https", "--silent", "--show-error", "--output", "/dev/null", "--write-out",
                "http_code=%{http_code}\nremote_ip=%{remote_ip}\nbytes=%{size_download}\ntotal_s=%{time_total}\nredirect_url=%{redirect_url}\n",
                url], timeout=23, check=False)
            values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
            status = int(values.get("http_code", "0"))
            web["hops"].append({"url": url, "resolved_ipv4": address, "exit_code": rc,
                                "http_code": status, "metrics": values, "output": output.strip()})
            print("HTTPS {}: HTTP={} exit={} IP={}".format(url, status, rc, address), flush=True)
            if rc:
                return
            if 200 <= status < 300:
                web["ok"] = True
                return
            if status not in (301, 302, 303, 307, 308) or not values.get("redirect_url"):
                web["error"] = "HTTP {} (a site-specific refusal is not proof of a BRAS failure)".format(status)
                return
            url = values["redirect_url"]
        web["error"] = "Too many redirects"

    def log_summary(self):
        logpath = self.out / "pppd.log"
        if not self.out_created or not logpath.exists():
            return
        text = logpath.read_text(errors="replace")
        self.report["authentication_succeeded"] = bool(re.search(r"(?:CHAP|PAP) authentication succeeded", text, re.I))
        if re.search(r"authentication failed|authentication failure|access denied", text, re.I):
            self.report["failure_stage"] = "AUTHENTICATION"
        elif re.search(r"Timeout waiting for PADO|Unable to complete PPPoE Discovery", text, re.I):
            self.report["failure_stage"] = "PPPOE_DISCOVERY"
        elif re.search(r"IPCP.*(timeout|terminated)|Could not determine.*IP", text, re.I):
            self.report["failure_stage"] = "IPCP"
        elif re.search(r"LCP terminated by peer", text, re.I):
            self.report["failure_stage"] = "PPP_PEER_TERMINATION"
            self.report["termination_reason"] = "Peer terminated LCP"
            self.report["terminated_before_ipv4"] = self.connected_monotonic is None
        mac = re.search(r"Connected to ([0-9a-f:]{17})", text, re.I)
        if mac:
            self.report["observed_ac_mac"] = mac.group(1).lower()
        session = re.search(r"PPP session is (\d+)", text)
        if session:
            self.report["pppoe_session_id"] = int(session.group(1))

    def cleanup(self):
        errors = []
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        try:
            self.stop_capture()
        except Exception as e:
            errors.append("Capture cleanup failed: " + str(e))
        if self.created:
            # Allow the private ip-down hook to finish before removing /etc/ppp.
            for _ in range(10):
                rc, pids = command(["ip", "netns", "pids", self.ns], check=False)
                if rc or not pids.strip():
                    break
                time.sleep(0.2)
            if not rc and pids.strip():
                errors.append("Processes remain in namespace: " + pids.strip())
            try:
                self.read_hook_events()
            except Exception as e:
                errors.append("Could not copy final IPCP events: " + str(e))
        if self.moved:
            try:
                # Delete only the test VLAN; move the same physical NIC back.
                if self.a.vlan:
                    command(["ip", "-n", self.ns, "link", "del", "testvlan"], check=False)
                there = command(["ip", "-n", self.ns, "link", "show", "dev", self.a.interface], check=False)[0] == 0
                if there:
                    command(["ip", "-n", self.ns, "link", "set", self.a.interface, "netns", os.getpid()])
                command(["ip", "link", "set", self.a.interface, "down"])
                for path, value in self.before["sysctls"].items():
                    try:
                        if Path(path).read_text().strip() != value:
                            Path(path).write_text(value + "\n")
                    except OSError as e:
                        errors.append("Restore sysctl {}: {}".format(path, e))
                command(["ip", "link", "set", self.a.interface, "mtu", self.before["link"]["mtu"]])
                for addr in self.before["addresses"]:
                    command(["ip", "-6", "address", "replace", addr["local"] + "/" + str(addr["prefixlen"]),
                             "dev", self.a.interface, "scope", "link"])
                if "UP" in self.before["link"]["flags"]:
                    command(["ip", "link", "set", self.a.interface, "up"])
                self.moved = False
                restored = ipjson("link", "show", "dev", self.a.interface)[0]
                restored_addresses = ipjson("address", "show", "dev", self.a.interface)[0]["addr_info"]
                addrset = lambda rows: {(r["family"], r["local"], r["prefixlen"]) for r in rows}
                self.report["interface_restored"] = (
                    restored["address"] == self.before["link"]["address"] and
                    restored["mtu"] == self.before["link"]["mtu"] and
                    ("UP" in restored["flags"]) == ("UP" in self.before["link"]["flags"]) and
                    addrset(restored_addresses) == addrset(self.before["addresses"]))
                if not self.report["interface_restored"]:
                    errors.append("Restored NIC attributes/addresses differ from original")
            except Exception as e:
                errors.append("NIC RESTORE FAILED: " + str(e))
        if self.created and not self.moved and not errors:
            rc, text = command(["ip", "netns", "del", self.ns], check=False)
            if rc:
                errors.append("Namespace delete failed: " + text)
        # Remove credentials even if recovery of the interface failed.
        if self.etc_created and self.etc.exists():
            shutil.rmtree(self.etc)
        if hasattr(self, "host_before"):
            after = host_state(self.a.interface)
            save(self.out / "host-after.json", after)
            unchanged = after == self.host_before
            self.report["host_routes_rules_dns_unchanged"] = unchanged
            if not unchanged:
                errors.append("Host routes/rules/DNS differ; compare host-before.json and host-after.json. No automatic route overwrite was attempted.")
        self.report["cleanup_ok"] = not errors
        self.report["cleanup_errors"] = errors
        return errors


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--interface", required=True)
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    p.add_argument("--bras", default="manual", help="Expected inventory label; not auto-verified")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--check", action="store_true", help="Read-only preflight (default)")
    transport = p.add_mutually_exclusive_group()
    transport.add_argument("--untagged", action="store_true")
    transport.add_argument("--vlan", type=int)
    p.add_argument("--service", default="")
    p.add_argument("--ac", default="")
    p.add_argument("--expect-mac")
    p.add_argument("--env-file", help="Credential file (default: .env beside this script)")
    p.add_argument("--ping", nargs="+", default=["8.8.4.4", "8.8.8.8", "77.88.8.8"])
    p.add_argument("--output", help="New report directory; must not already exist")
    p.add_argument("--namespace", help="Explicit namespace name; must not already exist")
    p.add_argument("--hold", action="store_true", help="After initial checks, keep connected until stopped; no reconnect")
    p.add_argument("--skip-initial-tests", action="store_true", help="With --hold, connect without traffic probes; SIGUSR1 still requests tests")
    p.add_argument("--capture-control", action="store_true", help="Capture our PPP control exchange for at most 75 s; requires tcpdump; excludes PAP requests and CHAP challenge/response")
    a = p.parse_args()
    if a.vlan is not None and not 1 <= a.vlan <= 4094:
        p.error("--vlan must be 1..4094")
    if a.run and not (a.untagged or a.vlan):
        p.error("Specify --untagged or --vlan; BRAS number is not a VLAN ID")
    if a.hold and not a.run:
        p.error("--hold requires --run")
    if a.skip_initial_tests and not a.hold:
        p.error("--skip-initial-tests requires --hold")
    if a.namespace and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,59}", a.namespace):
        p.error("Invalid --namespace (1..60 safe characters, no leading dot/dash)")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,60}", a.bras):
        p.error("--bras: use an inventory label with letters, digits, dots or dashes")
    if not 1 <= len(a.ping) <= 5:
        p.error("Use 1..5 ping targets")
    for target in a.ping:
        try:
            ipaddress.IPv4Address(target)
        except ValueError:
            p.error("Invalid IPv4 ping target: " + target)
    os.umask(0o077)
    try:
        env_path = Path(a.env_file).expanduser() if a.env_file else Path(__file__).resolve().with_name(".env")
        file_values = read_dotenv(env_path, required=a.env_file is not None)
        before = preflight(a)
        print("PREFLIGHT OK: {} MAC={} {}".format(a.interface, before["link"]["address"], before["pppd"]), flush=True)
        if not a.run:
            print("No network changes made. --run requires PPP credentials (.env, environment or terminal) and --untagged/--vlan.")
            return 0
        lock = open("/run/ispsupport-test-" + a.interface + ".lock", "w")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.namespace:
            namespace_lock = open("/run/ispsupport-netns-" + a.namespace + ".lock", "w")
            fcntl.flock(namespace_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        username, password = credentials(file_values)
        file_values = None
        if not username or not password:
            raise RuntimeError("Empty credentials")
        quote_option(username)
        quote_option(password)
        # Recheck after the prompt: the NIC may have changed in the meantime.
        before = preflight(a)
    except Exception as e:
        print("PREFLIGHT FAILED: " + str(e), file=sys.stderr)
        return 2
    test, rc = Test(a, before), 2
    stopped_signal = None
    def interrupted(signum, frame):
        nonlocal stopped_signal
        stopped_signal = signum
        raise KeyboardInterrupt("signal " + str(signum))
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, interrupted)
    if a.hold:
        def request_probe(signum, frame):
            test.probe_requested = True
        signal.signal(signal.SIGUSR1, request_probe)
    try:
        print("Report: " + str(test.out), flush=True)
        test.prepare(username, password)
        username = password = ""
        rc = test.hold() if a.hold else test.exercise()
    except KeyboardInterrupt:
        if a.hold:
            test.report.update(status="STOPPED", stop_signal=stopped_signal)
            test.event("STOP_REQUESTED", signal=stopped_signal)
            rc = 0
        else:
            test.report.update(status="INTERRUPTED", error="Interrupted by signal")
            rc = 130
    except Exception as e:
        test.report.update(status="ERROR", error=str(e))
        print("ERROR: " + str(e), file=sys.stderr)
    finally:
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGUSR1):
            signal.signal(s, signal.SIG_IGN)
        try:
            errors = test.cleanup()
            test.log_summary()
        except Exception as e:
            errors = [str(e)]
            test.report.update(cleanup_ok=False, cleanup_errors=errors)
        if errors:
            test.report["status"] = "CLEANUP_ERROR"
            rc = 3
            print("CLEANUP ERROR: " + "; ".join(errors), file=sys.stderr)
        if test.out_created:
            test.report["finished_utc"] = utcnow()
            test.report["ipv4_available"] = False
            save(test.out / "result.json", test.report)
        for name, item in test.report["checks"].items():
            print("CHECK {}: {}".format(name, "PASS" if item["ok"] else "FAIL"), flush=True)
        print("RESULT={} exit={} report={}".format(test.report["status"], rc, test.out / "result.json"), flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
