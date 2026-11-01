"""Incident findings: patterns across the merged timeline worth an analyst's eye.

Each rule maps to a MITRE ATT&CK technique so the report reads in the same
language a SOC or IR team uses.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from chronicle.timeline import Timeline, TimelineEvent

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
FAILED_LOGON_ACTIONS = {"ssh_login_failed", "ssh_invalid_user", "logon_failed"}
SUCCESS_LOGON_ACTIONS = {"ssh_login_success", "logon_success"}
SUSPICIOUS_COMMANDS = ("wget ", "curl ", "chmod +x", "base64 -d", "nc ", "crontab", "/dev/tcp/", "history -c")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    rule: str
    severity: str
    technique: str
    summary: str
    events: list[TimelineEvent] = field(default_factory=list)

    @property
    def first_seen(self):
        return min(e.timestamp for e in self.events)


def _brute_force_then_success(timeline: Timeline) -> list[Finding]:
    """Many failed logons from one IP, then a success from that same IP."""
    findings = []
    failures: dict[str, list[TimelineEvent]] = defaultdict(list)
    for event in timeline.events:
        if not event.src_ip:
            continue
        if event.action in FAILED_LOGON_ACTIONS:
            failures[event.src_ip].append(event)
        elif event.action in SUCCESS_LOGON_ACTIONS:
            recent = [f for f in failures[event.src_ip] if event.timestamp - f.timestamp <= BRUTE_FORCE_WINDOW]
            if len(recent) >= BRUTE_FORCE_THRESHOLD:
                findings.append(
                    Finding(
                        rule="brute_force_success",
                        severity="critical",
                        technique="T1110 Brute Force",
                        summary=(
                            f"{len(recent)} failed logons from {event.src_ip} followed by a successful "
                            f"logon as '{event.actor}' on {event.host}"
                        ),
                        events=recent + [event],
                    )
                )
            failures[event.src_ip].clear()
    return findings


def _single_event(timeline: Timeline, action: str, rule: str, severity: str, technique: str, text: str) -> list[Finding]:
    return [Finding(rule, severity, technique, text.format(e=e), [e]) for e in timeline.events if e.action == action]


def _suspicious_shell(timeline: Timeline) -> list[Finding]:
    findings = []
    for event in timeline.events:
        if event.action != "shell_command":
            continue
        hits = [s.strip() for s in SUSPICIOUS_COMMANDS if s in f"{event.description} "]
        if hits:
            findings.append(
                Finding(
                    rule="suspicious_shell_command",
                    severity="high",
                    technique="T1059.004 Unix Shell",
                    summary=f"'{event.actor}' ran '{event.description}' on {event.host} (matched: {', '.join(hits)})",
                    events=[event],
                )
            )
    return findings


def analyze(timeline: Timeline) -> list[Finding]:
    findings = _brute_force_then_success(timeline)
    findings += _single_event(
        timeline, "audit_log_cleared", "log_cleared", "critical", "T1070.001 Clear Windows Event Logs",
        "Security audit log cleared on {e.host} by '{e.actor}'",
    )
    findings += _single_event(
        timeline, "account_created", "account_created", "high", "T1136 Create Account",
        "New account '{e.actor}' created on {e.host}",
    )
    findings += _single_event(
        timeline, "group_membership_added", "group_membership_added", "high", "T1098 Account Manipulation",
        "'{e.actor}' added to a group on {e.host}: {e.description}",
    )
    findings += _single_event(
        timeline, "service_installed", "service_installed", "medium", "T1543.003 Windows Service",
        "New service installed on {e.host}: {e.description}",
    )
    findings += _suspicious_shell(timeline)
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen))
