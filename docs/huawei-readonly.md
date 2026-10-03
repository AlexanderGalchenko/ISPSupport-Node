# Huawei VRP operational collection

On-demand MAC, VSI/PW, LDP and Eth-Trunk collection through a persistent OpenSSH terminal.
The initial supported format is S6730-H48X6C / V200R022C00SPC500. It is not a configuration writer or an automatic device scanner.

Requirements: Python 3, OpenSSH client and the distribution `python3-pexpect` package. Use a restricted equipment account, an existing node-local private key, and a verified host-key entry. No passwords, configuration exports or private keys are collected. This command does not enroll unknown host keys.

```bash
python3 scripts/huawei_collect.py \
  --host 192.0.2.10 --user ispsupport \
  --key /root/.ssh/id_rsa \
  --known-hosts /var/lib/ispsupport-node/device_known_hosts \
  --legacy-rsa \
  --output /var/lib/ispsupport-node/huawei/report.json
```

`192.0.2.10` is a documentation address; supply the authorized equipment IP. `--legacy-rsa` permits ssh-rsa user signatures for this process only, for the tested older VRP behavior. It is opt-in and does not alter host-key algorithms or global SSH configuration. Prefer its omission on firmware that negotiates modern signatures correctly.

Use `--vsi EXAMPLE` to collect only that VSI's MAC entries. VSI/PW, LDP and Eth-Trunk states remain device-wide. `--json` prints structured output; otherwise a short Russian summary is printed. Protect stdout if it contains operator telemetry.

The JSON report contains a UTC collection timestamp, scope, parser errors and observations. A missing or rejected section is null, never an invented zero. Overall VSI Up does not hide an individual failed pseudowire. MAC entries are not a subscriber count, and observations are not confirmed incidents.

Execution is bounded to 120 seconds, 30 seconds per command, 4 MiB per response and 16 MiB per session. Output without a complete prompt is discarded. Files are atomically replaced with mode 0600. Fatal transport failures retain the previous file; check its timestamp and process exit code. Partial collections are saved with `complete: false` and section errors.

Exit status: 0 complete; 2 partial data; 1 fatal collection failure. No timer is installed by this script. Keep operator-specific keys, IPs and raw output outside the public repository.

```bash
python3 -m unittest discover -s tests -p test_huawei_collect.py -v
```
