"""Windows Security / System event log parser (JSON Lines export).

Expects one JSON object per line, as produced by EVTX-to-JSON converters or
``Get-WinEvent | ConvertTo-Json -Compress``. Field names are matched
case-insensitively and event data is read from an ``EventData`` object.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Iterable, Iterator

from chronicle.timeline import TimelineEvent

EVENT_IDS = {
    4624: ("logon_success", "An account logged on"),
    4625: ("logon_failed", "An account failed to log on"),
    4672: ("special_privileges_assigned", "Special privileges assigned to new logon"),
    4688: ("process_created", "A new process was created"),
    4720: ("account_created", "A user account was created"),
    4732: ("group_membership_added", "A member was added to a security-enabled local group"),
    1102: ("audit_log_cleared", "The audit log was cleared"),
    7045: ("service_installed", "A new service was installed"),
}
DETAIL_FIELDS = ("LogonType", "NewProcessName", "CommandLine", "ServiceName", "ImagePath")
LOCAL_ADDRESSES = {"-", "::1", "127.0.0.1"}


def _get(record: dict, *names: str, default=""):
    lowered = {k.lower(): v for k, v in record.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return value
    return default


def _parse_time(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    # EVTX tools often emit 7-digit fractions; Python accepts at most 6.
    if "." in value:
        head, _, tail = value.partition(".")
        digits = tail[: len(tail) - len(tail.lstrip("0123456789"))]
        zone = tail[len(digits):]
        value = f"{head}.{digits[:6].ljust(6, '0')}{zone}"
    return datetime.fromisoformat(value)


def parse_windows_events(lines: Iterable[str], artifact: str = "Security.evtx") -> Iterator[TimelineEvent]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            event_id = int(_get(record, "EventID", "Id", default=0))
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        if event_id not in EVENT_IDS:
            continue
        data = _get(record, "EventData", default={})
        if not isinstance(data, dict):
            data = {}
        action, label = EVENT_IDS[event_id]
        src_ip = str(_get(data, "IpAddress"))
        details = [f"{key}={_get(data, key)}" for key in DETAIL_FIELDS if _get(data, key)]
        if event_id == 4732:
            # For group changes TargetUserName is the group; the account added is MemberName.
            actor = _get(data, "MemberName", "MemberSid")
            details.insert(0, f"Group={_get(data, 'TargetUserName')}")
        else:
            actor = _get(data, "TargetUserName", "SubjectUserName")
        yield TimelineEvent(
            timestamp=_parse_time(str(_get(record, "TimeCreated", "Timestamp", "SystemTime"))),
            source="winevt",
            host=str(_get(record, "Computer", "MachineName", default="windows")),
            action=action,
            description=f"{event_id}: {label}" + (f" ({', '.join(details)})" if details else ""),
            actor=str(actor),
            src_ip="" if src_ip in LOCAL_ADDRESSES else src_ip,
            artifact=artifact,
            extra={"event_id": event_id, **data},
        )
