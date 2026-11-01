from datetime import datetime, timezone

from chronicle.parsers import (
    parse_access_log,
    parse_auth_log,
    parse_bash_history,
    parse_bodyfile,
    parse_windows_events,
)
from conftest import read_lines


def test_auth_log(samples):
    events = list(parse_auth_log(read_lines(samples / "auth.log"), year=2026))
    actions = [e.action for e in events]
    assert actions.count("ssh_login_failed") == 7
    assert actions.count("ssh_login_success") == 2
    assert "account_created" in actions
    assert actions.count("group_membership_added") == 1

    success = next(e for e in events if e.action == "ssh_login_success")
    assert success.actor == "deploy"
    assert success.src_ip == "203.0.113.45"
    assert success.host == "web01"
    assert success.timestamp == datetime(2026, 10, 14, 3, 19, 47)

    sudo = next(e for e in events if e.action == "sudo_command")
    assert sudo.extra["cmd"] == "/usr/sbin/useradd -m backup2"


def test_auth_log_single_digit_day():
    [event] = parse_auth_log(["Mar  3 10:00:00 db01 sshd[9]: Accepted password for root from 10.0.0.5 port 2 ssh2"], 2026)
    assert event.timestamp == datetime(2026, 3, 3, 10, 0, 0)


def test_auth_log_ignores_noise():
    lines = ["garbage", "Oct 14 03:19:47 web01 CRON[1]: pam_unix(cron:session): session closed for user root"]
    assert list(parse_auth_log(lines, 2026)) == []


def test_access_log(samples):
    events = list(parse_access_log(read_lines(samples / "access.log"), host="web01"))
    assert len(events) == 5
    assert sum(e.action == "http_error" for e in events) == 3
    authed = events[-1]
    assert authed.actor == "ops"
    assert authed.extra["user_agent"] == "curl/8.4.0"
    assert authed.timestamp.tzinfo is not None


def test_bash_history(samples):
    events = list(parse_bash_history(read_lines(samples / "bash_history_deploy"), host="web01", user="deploy"))
    assert [e.description for e in events][:2] == ["id", "uname -a"]
    assert events[0].timestamp == datetime(2026, 10, 14, 3, 20, 5, tzinfo=timezone.utc)


def test_bash_history_skips_untimestamped_commands():
    assert list(parse_bash_history(["ls", "pwd"], host="h", user="u")) == []


def test_bodyfile(samples):
    events = list(parse_bodyfile(read_lines(samples / "bodyfile.txt"), host="web01"))
    script = [e for e in events if e.extra["path"] == "/tmp/.x/update.sh"]
    assert {e.action for e in script} == {"file_accessed", "file_modified", "file_metadata_changed", "file_created"}
    crontab = [e for e in events if e.extra["path"].endswith("crontabs/deploy")]
    assert "file_accessed" not in {e.action for e in crontab}  # atime 0 is skipped


def test_windows_events(samples):
    events = list(parse_windows_events(read_lines(samples / "security_events.jsonl")))
    assert len(events) == 10  # 4634 logoff is not tracked
    first = events[0]
    assert first.action == "logon_failed"
    assert first.timestamp == datetime(2026, 10, 14, 3, 40, 2, 123456, tzinfo=timezone.utc)
    group_add = next(e for e in events if e.action == "group_membership_added")
    assert group_add.actor == "svc_backup"
    assert "Group=Administrators" in group_add.description
    cleared = next(e for e in events if e.action == "audit_log_cleared")
    assert cleared.actor == "jsmith"


def test_windows_events_skip_bad_lines():
    assert list(parse_windows_events(["not json", '{"EventID": "abc"}', ""])) == []
