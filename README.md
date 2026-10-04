# Security Engineering Home Lab

A small virtualized security lab built to practice attacker/defender workflows, network reconnaissance, Linux telemetry analysis, and Python-based detection engineering.

## Architecture

The lab uses two virtual machines connected through an isolated VirtualBox host-only network.

- **security-server** — Ubuntu Server
  - Host-only IP: `192.168.56.2`
  - Docker
  - OWASP Juice Shop on port `3000`
  - OpenSSH on port `22`

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
- Remaining scanned TCP ports closed

## Controlled SSH Attack Simulation

Repeated failed SSH login attempts were generated from the attacker VM:

```bash
ssh fakeuser@192.168.56.2
```

The server recorded the activity in the SSH system journal, including the attacker source IP `192.168.56.3`.

Example inspection command:

```bash
sudo journalctl -u ssh --since "10 minutes ago"
```

## Python Detection

A Python detector was created to analyze recent SSH logs and identify repeated failed authentication attempts.

The detector:

1. Reads recent SSH events using `journalctl`
2. Extracts source IP addresses from failed password events
3. Counts failed attempts per source
4. Generates an alert when the configured threshold is reached

Example output:

```text
ALERT: 192.168.56.3 generated 3 failed SSH login attempts
```

Detector location:

```text
scripts/detect_failed_ssh.py
```

## Current Workflow

```text
Attacker VM
    |
    | Nmap / failed SSH logins
    v
Ubuntu Security Server
    |
    | SSH telemetry
    v
systemd journal
    |
    v
Python detector
    |
    v
Alert on repeated authentication failures
```

## Skills Demonstrated

- VirtualBox networking
- Linux server administration
- Docker
- OWASP Juice Shop
- Network reconnaissance with Nmap
- SSH authentication telemetry
- Detection engineering
- Python automation
- Attacker/defender workflow analysis

## Next Steps

Planned improvements include:

- Unit tests for the detector
- Additional detections for reconnaissance and web activity
- Container and dependency scanning
- CI/CD integration
- SIEM/XDR integration such as Wazuh
