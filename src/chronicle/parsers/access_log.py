"""Apache / nginx combined log format parser."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator

from chronicle.timeline import TimelineEvent

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)


def parse_access_log(lines: Iterable[str], host: str = "web", artifact: str = "access.log") -> Iterator[TimelineEvent]:
    for line in lines:
        match = COMBINED.match(line.strip())
        if not match:
            continue
        status = int(match["status"])
        yield TimelineEvent(
            timestamp=datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z"),
            source="web",
            host=host,
            action="http_error" if status >= 400 else "http_request",
            description=f"{match['method']} {match['path']} -> {status}",
            actor="" if match["user"] == "-" else match["user"],
            src_ip=match["ip"],
            artifact=artifact,
            extra={
                "method": match["method"],
                "path": match["path"],
                "status": status,
                "user_agent": match["agent"] or "",
            },
        )
