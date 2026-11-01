"""Markdown incident report: evidence integrity, findings and timeline."""

from __future__ import annotations

from datetime import datetime, timezone

from chronicle.evidence import CaseFile
from chronicle.findings import Finding
from chronicle.timeline import Timeline

MAX_TIMELINE_ROWS = 500


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_report(case: CaseFile, timeline: Timeline, findings: list[Finding]) -> str:
    integrity = case.verify_evidence()
    chain_problems = case.verify_chain()
    events = timeline.events
    lines = [
        f"# Incident Report: {case.case_id}",
        "",
        f"- **Examiner:** {case.examiner or 'n/a'}",
        f"- **Generated:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- **Events analysed:** {len(events)}",
    ]
    if events:
        lines.append(f"- **Time span:** {events[0].timestamp.isoformat()} to {events[-1].timestamp.isoformat()}")
    lines += [
        f"- **Findings:** {len(findings)}",
        f"- **Custody chain:** {'intact' if not chain_problems else f'BROKEN ({len(chain_problems)} problems)'}",
        "",
        "## Evidence",
        "",
        "| ID | File | SHA-256 | Integrity |",
        "|---|---|---|---|",
    ]
    for result in integrity:
        lines.append(f"| {result.evidence_id} | `{_cell(result.path)}` | `{result.expected}` | {result.status} |")
    if chain_problems:
        lines += ["", "### Custody chain problems", ""]
        lines += [f"- entry {p.seq}: {p.reason}" for p in chain_problems]

    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings.")
    for number, finding in enumerate(findings, 1):
        lines += [
            f"### {number}. [{finding.severity.upper()}] {finding.rule}",
            "",
            f"- **ATT&CK:** {finding.technique}",
            f"- **First seen:** {finding.first_seen.isoformat()}",
            f"- {finding.summary}",
            "",
        ]

    lines += ["## Timeline", "", "| Time (UTC) | Host | Source | Action | Actor | Source IP | Detail |", "|---|---|---|---|---|---|---|"]
    for event in events[:MAX_TIMELINE_ROWS]:
        lines.append(
            f"| {event.timestamp.isoformat()} | {_cell(event.host)} | {event.source} | {event.action} | "
            f"{_cell(event.actor)} | {event.src_ip} | {_cell(event.description)} |"
        )
    if len(events) > MAX_TIMELINE_ROWS:
        lines.append(f"\n_{len(events) - MAX_TIMELINE_ROWS} more events omitted; export the full timeline as CSV._")
    return "\n".join(lines) + "\n"
