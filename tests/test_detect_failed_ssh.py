import sys
from pathlib import Path

sys.path.append(str(Path.home() / "security-lab" / "scripts"))

from detect_failed_ssh import detect_failed_logins


SAMPLE_LOG = """
Oct 04 13:33:01 security-server sshd[1001]: Failed password for invalid user fakeuser from 192.168.56.3 port 50123 ssh2
Oct 04 13:33:05 security-server sshd[1002]: Failed password for invalid user fakeuser from 192.168.56.3 port 50124 ssh2
Oct 04 13:33:09 security-server sshd[1003]: Failed password for invalid user fakeuser from 192.168.56.3 port 50125 ssh2
"""


def test_detects_repeated_failed_logins():
    alerts = detect_failed_logins(SAMPLE_LOG, threshold=3)

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "192.168.56.3"
    assert alerts[0]["count"] == 3
    assert alerts[0]["severity"] == "alert"


def test_does_not_alert_below_threshold():
    alerts = detect_failed_logins(SAMPLE_LOG, threshold=4)

    assert alerts == []
