# Chronicle

**Digital forensics and incident response toolkit.** Chronicle takes the artifacts you collect from compromised hosts, merges them into one UTC timeline, flags the activity an investigator needs to see first, and tracks every piece of evidence with a hash-chained chain of custody.

It has no dependencies outside the Python standard library, so it runs on an analysis workstation or a locked-down jump box.

```
$ chronicle report case.json --auth auth.log --bash deploy=.bash_history --winevt security.jsonl --year 2026

### 1. [CRITICAL] brute_force_success
- ATT&CK: T1110 Brute Force
- 8 failed logons from 203.0.113.45 followed by a successful logon as 'deploy' on web01

### 3. [CRITICAL] log_cleared
- ATT&CK: T1070.001 Clear Windows Event Logs
- Security audit log cleared on WS-FIN01 by 'jsmith'
```

## What it does

**Chain of custody.** Every evidence file is SHA-256 hashed when it's acquired. Each custody action (acquire, transfer, analyze, verify, release) is written to a ledger where every entry includes the hash of the previous one, the same idea as a blockchain or a Git history. If someone edits, deletes or reorders an entry, `chronicle verify` shows exactly which entry broke. It also re-hashes the evidence files and reports any that were modified or are missing.

**Unified timeline.** Parsers convert each artifact into common events, normalise every timestamp to UTC, drop exact duplicates and sort everything. You can filter by time window, host, user or source and export CSV (for Timeline Explorer or a spreadsheet) or JSON.

**Findings.** Rules run across the merged timeline, so they catch patterns that span sources, such as a brute force against one machine followed by persistence on another. Each finding maps to MITRE ATT&CK.

**Reports.** A Markdown incident report with evidence integrity status, custody chain status, findings ranked by severity, and the full timeline.

## Supported artifacts

| Flag | Artifact | Events extracted |
|---|---|---|
| `--auth` | Linux `auth.log` / `secure` | SSH failed / invalid / accepted logons, sudo commands, account creation, group changes |
| `--access` | Apache / nginx combined log | Requests and errors, with client IP, user and user agent |
| `--bash USER=PATH` | `.bash_history` written with `HISTTIMEFORMAT` | Timestamped shell commands |
| `--bodyfile` | Sleuth Kit bodyfile (`fls -m`) | File accessed / modified / metadata changed / created (MACB) |
| `--winevt` | Windows Security & System events as JSON Lines | 4624, 4625, 4672, 4688, 4720, 4732, 1102, 7045 |

## Detection rules

| Rule | Severity | ATT&CK | Logic |
|---|---|---|---|
| `brute_force_success` | Critical | T1110 Brute Force | 5+ failed logons from one IP, then a successful logon from that IP within 10 minutes |
| `log_cleared` | Critical | T1070.001 Clear Windows Event Logs | Event 1102 |
| `account_created` | High | T1136 Create Account | `useradd` or event 4720 |
| `group_membership_added` | High | T1098 Account Manipulation | `usermod -aG` or event 4732 |
| `suspicious_shell_command` | High | T1059.004 Unix Shell | Download, make-executable, decode, reverse shell, cron and history-wipe patterns |
| `service_installed` | Medium | T1543.003 Windows Service | Event 7045 |

## Usage

```bash
pip install -e .

# 1. Open a case and acquire evidence
chronicle init case.json --case-id IR-2026-014 --examiner "Your Name"
chronicle acquire case.json /cases/web01/auth.log --handler pjay --description "web01 auth log"
chronicle acquire case.json /cases/ws-fin01/security.jsonl --handler pjay

# 2. Log custody as evidence moves
chronicle custody case.json EV-001 transfer --handler pjay --notes "copied to evidence share"

# 3. Prove nothing changed (exit code 2 if anything was modified or the ledger was tampered with)
chronicle verify case.json --handler pjay

# 4. Build the timeline for a window
chronicle timeline --auth auth.log --winevt security.jsonl --year 2026 \
  --start 2026-10-14T03:00:00Z --end 2026-10-14T04:00:00Z --format csv > timeline.csv

# 5. Write the report
chronicle report case.json --auth auth.log --bash deploy=bash_history --winevt security.jsonl \
  --bodyfile bodyfile.txt --host web01 --year 2026 -o report.md
```

Syslog lines don't include a year, so pass `--year` for `auth.log`. Artifacts that don't record a host name (bash history, bodyfile, access logs) use `--host`.

## Sample incident

`samples/` holds a small synthetic intrusion you can run end to end: an SSH brute force against `web01`, a payload downloaded and made executable, a backdoor account added to `sudo`, a cron check and a history wipe. Then the same IP brute-forces `WS-FIN01`, creates `svc_backup`, adds it to Administrators, installs a service and clears the Security log. All IPs come from the documentation ranges (RFC 5737).

```bash
cd samples
chronicle init case.json --case-id IR-2026-014
chronicle acquire case.json auth.log --handler you
chronicle report case.json --auth auth.log --bash deploy=bash_history_deploy \
  --winevt security_events.jsonl --bodyfile bodyfile.txt --access access.log --host web01 --year 2026
```

## Project layout

```
src/chronicle/
  evidence.py      chain of custody ledger, evidence hashing and verification
  timeline.py      event model, UTC normalisation, dedupe, filters, CSV/JSON export
  findings.py      cross-source detection rules mapped to MITRE ATT&CK
  report.py        Markdown incident report
  cli.py           command-line interface
  parsers/         auth.log, access log, bash history, bodyfile, Windows events
tests/             unit and end-to-end tests
samples/           synthetic incident artifacts
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
