import re
import subprocess
from collections import defaultdict

PORT_THRESHOLD = 5


def extract_connection_attempts(log_text):
    """
    Extract source IP and destination port pairs from firewall log entries.
    Expected fields include SRC=<ip> and DPT=<port>.
    """
    pattern = re.compile(
        r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)"
    )

    return [
        (ip, int(port))
        for ip, port in pattern.findall(log_text)
    ]


def detect_port_scans(log_text, threshold=PORT_THRESHOLD):
    """
    Alert when a source IP attempts connections to at least `threshold`
    distinct destination ports.
    """
    ports_by_ip = defaultdict(set)

    for ip, port in extract_connection_attempts(log_text):
        ports_by_ip[ip].add(port)

    alerts = []

    for ip, ports in ports_by_ip.items():
        if len(ports) >= threshold:
            alerts.append(
                {
                    "ip": ip,
                    "unique_ports": len(ports),
                    "ports": sorted(ports),
                    "severity": "alert",
                }
            )

    return alerts


def get_recent_firewall_logs(minutes=15):
    result = subprocess.run(
        [
            "journalctl",
            "-k",
            "--since",
            f"{minutes} minutes ago",
            "--no-pager",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout


def main():
    log_text = get_recent_firewall_logs()
    alerts = detect_port_scans(log_text)

    if not alerts:
        print("No port-scan activity detected.")
        return

    for alert in alerts:
        print(
            f"ALERT: {alert['ip']} attempted connections to "
            f"{alert['unique_ports']} unique ports: "
            f"{alert['ports']}"
        )


if __name__ == "__main__":
    main()
