import csv
import io
import json
from datetime import datetime, timedelta, timezone

from chronicle.timeline import Timeline, TimelineEvent

MST = timezone(timedelta(hours=-7))


def event(ts, action="x", host="h1", **kw):
    return TimelineEvent(timestamp=ts, source="test", host=host, action=action, description=action, **kw)


def test_events_are_sorted_and_normalised_to_utc():
    timeline = Timeline(
        [
            event(datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc), "b"),
            event(datetime(2026, 1, 1, 4, 0, tzinfo=MST), "a"),  # 11:00 UTC
            event(datetime(2026, 1, 1, 13, 0), "c"),  # naive -> UTC
        ]
    )
    assert [e.action for e in timeline.events] == ["a", "b", "c"]
    assert all(e.timestamp.tzinfo == timezone.utc for e in timeline.events)


def test_exact_duplicates_are_dropped():
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    timeline = Timeline()
    assert timeline.add(event(ts)) is True
    assert timeline.add(event(ts)) is False
    assert len(timeline) == 1


def test_window_and_filter():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    timeline = Timeline([event(base + timedelta(hours=i), f"e{i}", host="h1" if i % 2 else "h2") for i in range(6)])
    window = timeline.window(base + timedelta(hours=1), base + timedelta(hours=3))
    assert [e.action for e in window.events] == ["e1", "e2", "e3"]
    assert [e.action for e in timeline.filter(host="h2").events] == ["e0", "e2", "e4"]


def test_exports():
    timeline = Timeline([event(datetime(2026, 1, 1, tzinfo=timezone.utc), "login", actor="root", src_ip="10.0.0.1")])
    rows = list(csv.DictReader(io.StringIO(timeline.to_csv())))
    assert rows[0]["actor"] == "root"
    assert rows[0]["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert json.loads(timeline.to_json())[0]["src_ip"] == "10.0.0.1"
