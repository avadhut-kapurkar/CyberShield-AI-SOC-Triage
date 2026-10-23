"""Alert normalization and validation. Alert text is UNTRUSTED input."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_TITLE = 200
MAX_DESC = 4000
MIN_DESC = 5


class AlertValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Alert:
    title: str
    description: str
    source_ip: str = ""
    host: str = ""

    def to_state(self) -> str:
        """Text the Decider reads. Plain facts, no instructions."""
        lines = [f"Alert title: {self.title}"]
        if self.host:
            lines.append(f"Host: {self.host}")
        if self.source_ip:
            lines.append(f"Source IP: {self.source_ip}")
        lines.append(f"Description: {self.description}")
        return "\n".join(lines)


def _clean(value: str | None) -> str:
    return _CTRL.sub("", value or "").strip()


def normalize_alert(title: str, description: str, source_ip: str = "", host: str = "") -> Alert:
    title, description = _clean(title), _clean(description)
    source_ip, host = _clean(source_ip), _clean(host)
    if not title:
        raise AlertValidationError("Title is required.")
    if len(title) > MAX_TITLE:
        raise AlertValidationError(f"Title must be at most {MAX_TITLE} characters.")
    if len(description) < MIN_DESC:
        raise AlertValidationError("Description is too short to classify.")
    if len(description) > MAX_DESC:
        raise AlertValidationError(f"Description must be at most {MAX_DESC} characters.")
    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError as exc:
            raise AlertValidationError(f"Invalid IP address: {source_ip!r}") from exc
    if len(host) > 100:
        raise AlertValidationError("Host name too long.")
    return Alert(title=title, description=description, source_ip=source_ip, host=host)


SAMPLE_ALERTS = {
    "Multiple failed logins from one IP": dict(
        title="Repeated failed SSH logins",
        description="48 failed SSH login attempts for user 'admin' within 3 minutes from a single external IP. No successful login observed.",
        source_ip="203.0.113.45", host="web-01"),
    "Suspicious PowerShell process": dict(
        title="Encoded PowerShell launched by Office app",
        description="WINWORD.EXE spawned powershell.exe with -EncodedCommand and -WindowStyle Hidden. The command connects to an unknown external host.",
        source_ip="", host="LAPTOP-FIN-07"),
    "Possible ransomware indicator": dict(
        title="Mass file rename with unknown extension",
        description="Over 2,000 files renamed to .locked in 90 seconds on a file server, and a ransom note README_RESTORE.txt appeared in multiple folders.",
        source_ip="", host="fileserver-02"),
    "Routine successful login": dict(
        title="Successful login",
        description="User alice logged in successfully from the corporate office network during normal working hours using MFA.",
        source_ip="198.51.100.10", host="vpn-gw"),
    "Simulated port scan": dict(
        title="Port scan (authorized test)",
        description="Sequential connection attempts to 1,000 ports from the internal scanner during the scheduled penetration test window.",
        source_ip="10.0.0.99", host="dmz-01"),
}