import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT / "scripts"))

from detect_port_scan import detect_port_scans


SAMPLE_LOG = """
Oct 04 15:34:01 security-server kernel: [UFW BLOCK] IN=enp0s9 OUT= MAC=... SRC=192.168.56.3 DST=192.168.56.2 PROTO=TCP SPT=50001 DPT=21
Oct 04 15:34:02 security-server kernel: [UFW BLOCK] IN=enp0s9 OUT= MAC=... SRC=192.168.56.3 DST=192.168.56.2 PROTO=TCP SPT=50002 DPT=23
Oct 04 15:34:03 security-server kernel: [UFW BLOCK] IN=enp0s9 OUT= MAC=... SRC=192.168.56.3 DST=192.168.56.2 PROTO=TCP SPT=50003 DPT=25
Oct 04 15:34:04 security-server kernel: [UFW BLOCK] IN=enp0s9 OUT= MAC=... SRC=192.168.56.3 DST=192.168.56.2 PROTO=TCP SPT=50004 DPT=53
Oct 04 15:34:05 security-server kernel: [UFW BLOCK] IN=enp0s9 OUT= MAC=... SRC=192.168.56.3 DST=192.168.56.2 PROTO=TCP SPT=50005 DPT=80
"""


def test_detects_port_scan_at_threshold():
    alerts = detect_port_scans(SAMPLE_LOG, threshold=5)

    assert len(alerts) == 1
    assert alerts[0]["ip"] == "192.168.56.3"
    assert alerts[0]["unique_ports"] == 5
    assert alerts[0]["ports"] == [21, 23, 25, 53, 80]
    assert alerts[0]["severity"] == "alert"


def test_does_not_alert_below_threshold():
    alerts = detect_port_scans(SAMPLE_LOG, threshold=6)

    assert alerts == []
