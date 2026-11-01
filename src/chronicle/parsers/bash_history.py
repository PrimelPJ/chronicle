"""bash history parser.

Only histories written with HISTTIMEFORMAT set carry timestamps: each command
is preceded by a ``#<epoch>`` line. Commands without a timestamp are skipped
because they can't be placed on a timeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Iterator

from chronicle.timeline import TimelineEvent


def parse_bash_history(
    lines: Iterable[str], host: str, user: str, artifact: str = ".bash_history"
) -> Iterator[TimelineEvent]:
    pending: datetime | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        if line.startswith("#") and line[1:].isdigit():
            pending = datetime.fromtimestamp(int(line[1:]), tz=timezone.utc)
            continue
        if pending is None or not line.strip():
            continue
        yield TimelineEvent(
            timestamp=pending,
            source="shell",
            host=host,
            action="shell_command",
            description=line.strip(),
            actor=user,
            artifact=artifact,
        )
        pending = None
