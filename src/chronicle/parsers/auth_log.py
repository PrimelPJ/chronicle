"""Linux auth.log / secure parser (sshd, sudo, useradd, usermod).

Syslog lines carry no year, so the caller passes the year the log covers.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator

from chronicle.timeline import TimelineEvent

SYSLOG = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-/.]+)(?:\[\d+\])?: (?P<msg>.*)$"
)

RULES = [
    ("ssh_login_failed", re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("ssh_invalid_user", re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("ssh_login_success", re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")),
    ("sudo_command", re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<cmd>.*)$")),
    ("account_created", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("group_membership_added", re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")),
]


def parse_auth_log(lines: Iterable[str], year: int, artifact: str = "auth.log") -> Iterator[TimelineEvent]:
    for line in lines:
        match = SYSLOG.match(line.rstrip("\n"))
        if not match:
            continue
        msg = match["msg"]
        for action, pattern in RULES:
            found = pattern.search(msg)
            if not found:
                continue
            groups = found.groupdict()
            ts = datetime.strptime(f"{year} {' '.join(match['ts'].split())}", "%Y %b %d %H:%M:%S")
            yield TimelineEvent(
                timestamp=ts,
                source="auth",
                host=match["host"],
                action=action,
                description=msg.strip(),
                actor=groups.get("user", ""),
                src_ip=groups.get("ip", ""),
                artifact=artifact,
                extra={k: v for k, v in groups.items() if k not in ("user", "ip")},
            )
            break
