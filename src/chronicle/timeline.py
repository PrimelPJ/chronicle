"""Unified forensic timeline.

Parsers turn artifacts into ``TimelineEvent`` objects. The ``Timeline``
normalises them to UTC, drops exact duplicates, sorts them, filters by time
window or host, and exports CSV or JSON.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass(order=True)
class TimelineEvent:
    timestamp: datetime
    source: str = field(compare=False)
    host: str = field(compare=False)
    action: str = field(compare=False)
    description: str = field(compare=False)
    actor: str = field(default="", compare=False)
    src_ip: str = field(default="", compare=False)
    artifact: str = field(default="", compare=False)
    extra: dict = field(default_factory=dict, compare=False)

    def key(self) -> tuple:
        return (self.timestamp, self.source, self.host, self.action, self.description)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


def to_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


class Timeline:
    def __init__(self, events: list[TimelineEvent] | None = None):
        self._events: list[TimelineEvent] = []
        self._seen: set[tuple] = set()
        for event in events or []:
            self.add(event)

    def add(self, event: TimelineEvent) -> bool:
        event.timestamp = to_utc(event.timestamp)
        key = event.key()
        if key in self._seen:
            return False
        self._seen.add(key)
        self._events.append(event)
        return True

    def extend(self, events) -> int:
        return sum(self.add(e) for e in events)

    @property
    def events(self) -> list[TimelineEvent]:
        return sorted(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def window(self, start: datetime | None = None, end: datetime | None = None) -> "Timeline":
        start = to_utc(start) if start else None
        end = to_utc(end) if end else None
        return Timeline(
            [e for e in self.events if (not start or e.timestamp >= start) and (not end or e.timestamp <= end)]
        )

    def filter(self, host: str | None = None, actor: str | None = None, source: str | None = None) -> "Timeline":
        return Timeline(
            [
                e
                for e in self.events
                if (host is None or e.host == host)
                and (actor is None or e.actor == actor)
                and (source is None or e.source == source)
            ]
        )

    def to_csv(self) -> str:
        out = io.StringIO()
        columns = ["timestamp", "host", "source", "action", "actor", "src_ip", "description", "artifact"]
        writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for event in self.events:
            writer.writerow(event.to_dict())
        return out.getvalue()

    def to_json(self) -> str:
        return json.dumps([e.to_dict() for e in self.events], indent=2)
