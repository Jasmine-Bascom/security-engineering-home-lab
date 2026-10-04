# Security Engineering Home Lab

A virtualized security lab built to practice attacker/defender workflows, network reconnaissance, Linux telemetry analysis, firewall monitoring, Python-based detection engineering, and automated validation.

## Architecture

The lab uses two virtual machines connected through an isolated VirtualBox host-only network.

- **security-server** — Ubuntu Server
  - Host-only IP: `192.168.56.2`
  - Docker
  - OWASP Juice Shop on port `3000`
  - OpenSSH on port `22`
  - UFW firewall with logging enabled

- **attacker** — Ubuntu Desktop
  - Host-only IP: `192.168.56.3`
  - Nmap
  - SSH client

Both VMs also use NAT adapters for outbound internet access.

## Attack Surface Reconnaissance

From the attacker VM, the server was scanned with:

```bash
nmap -sV 192.168.56.2
```

The scan identified:

- `22/tcp` — OpenSSH
- `3000/tcp` — OWASP Juice Shop
- Remaining scanned TCP ports closed or filtered

## Detection 1: Repeated Failed SSH Logins

Controlled failed SSH login attempts were generated from the attacker VM:

```bash
ssh fakeuser@192.168.56.2
```

The server recorded the activity in the SSH system journal, including the attacker source IP `192.168.56.3`.

Example inspection command:

```bash
sudo journalctl -u ssh --since "10 minutes ago"
```

A Python detector analyzes recent SSH events, extracts source IP addresses from failed password messages, counts repeated failures, and generates an alert when the threshold is reached.

Example output:

```text
ALERT: 192.168.56.3 generated 3 failed SSH login attempts
```

Detector:

```text
scripts/detect_failed_ssh.py
```

## Detection 2: Port Scan Activity

UFW firewall logging was enabled on the server, and a controlled Nmap scan was launched from the attacker VM:

```bash
nmap -Pn -p 1-100 192.168.56.2
```

UFW recorded the blocked connection attempts in the kernel journal.

The port-scan detector parses firewall telemetry, groups destination ports by source IP, and alerts when a single source attempts connections to multiple distinct ports.

Example output:

```text
ALERT: 192.168.56.3 attempted connections to 9 unique ports
```

Detector:

```text
scripts/detect_port_scan.py
```

## Automated Tests

The project includes pytest coverage for both detectors.

Current tests verify:

- repeated SSH failures trigger an alert at the configured threshold
- SSH activity below the threshold does not trigger an alert
- multi-port scan activity triggers an alert at the configured threshold
- activity below the port-scan threshold does not trigger an alert

Run locally with:

```bash
python3 -m pytest -v
```

Current result:

```text
4 passed
```

## GitHub Actions CI

A GitHub Actions workflow runs the pytest suite automatically on pushes and pull requests.

Workflow:

```text
.github/workflows/tests.yml
```

This provides continuous validation of the detection logic and helps catch regressions when the code changes.

## Current Workflow

```text
Attacker VM
    |
    |-- Failed SSH logins --------------------.
    |                                         |
    |                                         v
    |                                  SSH system journal
    |                                         |
    |                                         v
    |                              detect_failed_ssh.py
    |                                         |
    |                                         v
    |                                      ALERT
    |
    |-- Nmap port scan -----------------------.
                                              |
                                              v
                                       UFW/kernel logs
                                              |
                                              v
                                    detect_port_scan.py
                                              |
                                              v
                                           ALERT
```

## Skills Demonstrated

- VirtualBox networking
- Linux server administration
- Docker
- OWASP Juice Shop
- Nmap reconnaissance
- UFW firewall configuration and telemetry
- SSH authentication telemetry
- Detection engineering
- Python automation
- Pytest
- GitHub Actions CI
- Attacker/defender workflow analysis

## Next Steps

Planned improvements include:

- additional detections for suspicious web activity
- container and dependency scanning
- static analysis of the Python detection code
- richer test fixtures and edge cases
- SIEM/XDR integration such as Wazuh
- expanded documentation and architecture diagrams

