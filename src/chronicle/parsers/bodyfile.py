"""Sleuth Kit bodyfile parser (filesystem MAC times).

Format (TSK 3.x), pipe-separated:
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

Each non-zero timestamp becomes its own event, the same way ``mactime`` does,
so a file appears when it was created, modified, accessed and when its
metadata changed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Iterator

from chronicle.timeline import TimelineEvent

TIME_FIELDS = [
    (7, "file_accessed", "a"),
    (8, "file_modified", "m"),
    (9, "file_metadata_changed", "c"),
    (10, "file_created", "b"),
]


def parse_bodyfile(lines: Iterable[str], host: str, artifact: str = "bodyfile") -> Iterator[TimelineEvent]:
    for line in lines:
        parts = line.rstrip("\n").split("|")
        if len(parts) != 11:
            continue
        name, mode, uid, size = parts[1], parts[3], parts[4], parts[6]
        for index, action, flag in TIME_FIELDS:
            try:
                epoch = int(parts[index])
            except ValueError:
                continue
            if epoch <= 0:
                continue
            yield TimelineEvent(
                timestamp=datetime.fromtimestamp(epoch, tz=timezone.utc),
                source="filesystem",
                host=host,
                action=action,
                description=f"[{flag}] {name}",
                actor=uid,
                artifact=artifact,
                extra={"path": name, "mode": mode, "size": int(size) if size.isdigit() else size},
            )
