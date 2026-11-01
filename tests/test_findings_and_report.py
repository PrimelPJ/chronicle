from datetime import datetime, timedelta, timezone

from chronicle.cli import main
from chronicle.evidence import CaseFile
from chronicle.findings import analyze
from chronicle.parsers import parse_auth_log, parse_bash_history, parse_windows_events
from chronicle.report import render_report
from chronicle.timeline import Timeline, TimelineEvent
from conftest import read_lines


def sample_timeline(samples) -> Timeline:
    timeline = Timeline()
    timeline.extend(parse_auth_log(read_lines(samples / "auth.log"), year=2026))
    timeline.extend(parse_bash_history(read_lines(samples / "bash_history_deploy"), host="web01", user="deploy"))
    timeline.extend(parse_windows_events(read_lines(samples / "security_events.jsonl")))
    return timeline


def test_sample_incident_findings(samples):
    findings = analyze(sample_timeline(samples))
    rules = [f.rule for f in findings]
    assert rules.count("brute_force_success") == 2  # web01 over SSH, WS-FIN01 over SMB/RDP
    assert "log_cleared" in rules
    assert rules.count("account_created") == 2
    assert rules.count("group_membership_added") == 2
    assert "service_installed" in rules
    assert rules.count("suspicious_shell_command") == 4  # wget, chmod +x, crontab, history -c
    assert findings[0].severity == "critical"


def test_brute_force_needs_threshold_and_window():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def ev(minutes, action):
        return TimelineEvent(base + timedelta(minutes=minutes), "auth", "h", action, action, actor="u", src_ip="1.2.3.4")

    few = Timeline([ev(i, "ssh_login_failed") for i in range(4)] + [ev(5, "ssh_login_success")])
    assert analyze(few) == []
    stale = Timeline([ev(i, "ssh_login_failed") for i in range(5)] + [ev(30, "ssh_login_success")])
    assert analyze(stale) == []
    hit = Timeline([ev(i, "ssh_login_failed") for i in range(5)] + [ev(6, "ssh_login_success")])
    assert [f.rule for f in analyze(hit)] == ["brute_force_success"]


def test_report_contains_evidence_findings_and_timeline(samples, tmp_path):
    case = CaseFile(tmp_path / "case.json", "IR-2026-014", "Analyst")
    case.acquire(samples / "auth.log", handler="analyst")
    timeline = sample_timeline(samples)
    report = render_report(case, timeline, analyze(timeline))
    assert report.startswith("# Incident Report: IR-2026-014")
    assert "| EV-001 |" in report and "| OK |" in report
    assert "Custody chain:** intact" in report
    assert "T1110 Brute Force" in report
    assert "203.0.113.45" in report


def test_cli_end_to_end(samples, tmp_path, capsys):
    case_path = str(tmp_path / "case.json")
    assert main(["init", case_path, "--case-id", "IR-1", "--examiner", "A"]) == 0
    assert main(["init", case_path, "--case-id", "IR-1"]) == 1  # no overwrite
    assert main(["acquire", case_path, str(samples / "auth.log"), "--handler", "a"]) == 0
    assert main(["custody", case_path, "EV-001", "transfer", "--handler", "a", "--notes", "locker"]) == 0
    assert main(["verify", case_path, "--handler", "a"]) == 0
    assert len(CaseFile.load(case_path).ledger) == 3

    report_path = tmp_path / "report.md"
    args = ["report", case_path, "--auth", str(samples / "auth.log"), "--year", "2026", "-o", str(report_path)]
    assert main(args) == 0
    assert "brute_force_success" in report_path.read_text()

    capsys.readouterr()
    assert main(["timeline", "--auth", str(samples / "auth.log"), "--year", "2026", "--start", "2026-10-14T03:19:00Z"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("timestamp,host")
    assert len(out) == 1 + 6  # header + deploy login, 2 sudo, useradd, usermod, ops login


def test_cli_verify_fails_on_tampering(tmp_path):
    artifact = tmp_path / "a.log"
    artifact.write_text("original")
    case_path = str(tmp_path / "case.json")
    main(["init", case_path, "--case-id", "IR-2"])
    main(["acquire", case_path, str(artifact), "--handler", "a"])
    artifact.write_text("changed")
    assert main(["verify", case_path]) == 2
