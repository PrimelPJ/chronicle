"""Command-line interface.

    chronicle init CASE.json --case-id IR-2026-014 --examiner "Jane Doe"
    chronicle acquire CASE.json auth.log --handler jdoe --description "web01 auth log"
    chronicle custody CASE.json EV-001 transfer --handler jdoe --notes "to evidence locker"
    chronicle verify CASE.json --handler jdoe
    chronicle timeline CASE.json --auth auth.log --year 2026 --format csv
    chronicle report CASE.json --auth auth.log --year 2026 -o report.md
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from chronicle.evidence import CaseFile
from chronicle.findings import analyze
from chronicle.parsers import (
    parse_access_log,
    parse_auth_log,
    parse_bash_history,
    parse_bodyfile,
    parse_windows_events,
)
from chronicle.report import render_report
from chronicle.timeline import Timeline


def _read(path: str) -> list[str]:
    return Path(path).read_text(errors="replace").splitlines()


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_timeline(args: argparse.Namespace) -> Timeline:
    timeline = Timeline()
    for path in args.auth or []:
        timeline.extend(parse_auth_log(_read(path), year=args.year, artifact=Path(path).name))
    for path in args.access or []:
        timeline.extend(parse_access_log(_read(path), host=args.host, artifact=Path(path).name))
    for spec in args.bash or []:
        user, _, path = spec.partition("=")
        timeline.extend(parse_bash_history(_read(path), host=args.host, user=user, artifact=Path(path).name))
    for path in args.bodyfile or []:
        timeline.extend(parse_bodyfile(_read(path), host=args.host, artifact=Path(path).name))
    for path in args.winevt or []:
        timeline.extend(parse_windows_events(_read(path), artifact=Path(path).name))
    if args.start or args.end:
        timeline = timeline.window(_iso(args.start) if args.start else None, _iso(args.end) if args.end else None)
    return timeline


def _add_sources(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--auth", action="append", help="Linux auth.log / secure")
    parser.add_argument("--access", action="append", help="Apache/nginx combined access log")
    parser.add_argument("--bash", action="append", metavar="USER=PATH", help="timestamped bash history")
    parser.add_argument("--bodyfile", action="append", help="Sleuth Kit bodyfile")
    parser.add_argument("--winevt", action="append", help="Windows events as JSON Lines")
    parser.add_argument("--year", type=int, default=datetime.now(timezone.utc).year, help="year for syslog lines")
    parser.add_argument("--host", default="host", help="host name for artifacts that don't record one")
    parser.add_argument("--start", help="ISO 8601 window start")
    parser.add_argument("--end", help="ISO 8601 window end")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chronicle", description="DFIR timeline and chain of custody toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a case file")
    p.add_argument("case")
    p.add_argument("--case-id", required=True)
    p.add_argument("--examiner", default="")

    p = sub.add_parser("acquire", help="hash a file and log its acquisition")
    p.add_argument("case")
    p.add_argument("path")
    p.add_argument("--handler", required=True)
    p.add_argument("--description", default="")

    p = sub.add_parser("custody", help="log a custody action for an evidence item")
    p.add_argument("case")
    p.add_argument("evidence_id")
    p.add_argument("action", choices=["transfer", "analyze", "release"])
    p.add_argument("--handler", required=True)
    p.add_argument("--notes", default="")

    p = sub.add_parser("verify", help="re-hash evidence and check the custody chain")
    p.add_argument("case")
    p.add_argument("--handler", default="", help="log the verification in the ledger")

    p = sub.add_parser("timeline", help="build a merged timeline")
    p.add_argument("case", nargs="?")
    p.add_argument("--format", choices=["csv", "json"], default="csv")
    _add_sources(p)

    p = sub.add_parser("report", help="write a Markdown incident report")
    p.add_argument("case")
    p.add_argument("-o", "--output")
    _add_sources(p)

    args = parser.parse_args(argv)

    if args.command == "init":
        if Path(args.case).exists():
            print(f"refusing to overwrite existing case file {args.case}", file=sys.stderr)
            return 1
        CaseFile(args.case, args.case_id, args.examiner).save()
        print(f"created case {args.case_id} at {args.case}")
        return 0

    if args.command == "timeline":
        timeline = build_timeline(args)
        sys.stdout.write(timeline.to_csv() if args.format == "csv" else timeline.to_json() + "\n")
        return 0

    case = CaseFile.load(args.case)

    if args.command == "acquire":
        item = case.acquire(args.path, args.handler, args.description)
        case.save()
        print(f"{item.evidence_id}  {item.sha256}  {item.path}")
        return 0

    if args.command == "custody":
        entry = case.record(args.evidence_id, args.action, args.handler, args.notes)
        case.save()
        print(f"logged entry {entry.seq}: {entry.action} {entry.evidence_id} by {entry.handler}")
        return 0

    if args.command == "verify":
        results = case.verify_evidence(handler=args.handler)
        problems = case.verify_chain()
        if args.handler:
            case.save()
        for result in results:
            print(f"{result.evidence_id}  {result.status:8}  {result.path}")
        for problem in problems:
            print(f"custody chain: entry {problem.seq}: {problem.reason}")
        print("custody chain intact" if not problems else "custody chain BROKEN")
        return 0 if all(r.ok for r in results) and not problems else 2

    if args.command == "report":
        timeline = build_timeline(args)
        report = render_report(case, timeline, analyze(timeline))
        if args.output:
            Path(args.output).write_text(report)
            print(f"wrote {args.output}")
        else:
            sys.stdout.write(report)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
