import re
import subprocess
from collections import Counter

THRESHOLD = 3


def extract_failed_ips(log_text):
    pattern = re.compile(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)")
    return pattern.findall(log_text)


def detect_failed_logins(log_text, threshold=THRESHOLD):
    ips = extract_failed_ips(log_text)
    counts = Counter(ips)

    alerts = []

    for ip, count in counts.items():
        if count >= threshold:
            alerts.append(
                {
                    "ip": ip,
                    "count": count,
                    "severity": "alert",
                }
            )

    return alerts


def get_recent_ssh_logs(minutes=15):
    result = subprocess.run(
        [
            "journalctl",
            "-u",
            "ssh",
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
    log_text = get_recent_ssh_logs()
    alerts = detect_failed_logins(log_text)

    if not alerts:
        print("No repeated failed SSH login attempts detected.")
        return

    for alert in alerts:
        print(
            f"ALERT: {alert['ip']} generated "
            f"{alert['count']} failed SSH login attempts"
        )


if __name__ == "__main__":
    main()
