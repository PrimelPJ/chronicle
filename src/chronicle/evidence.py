"""Evidence tracking with a tamper-evident chain of custody.

Every evidence item is hashed (SHA-256) when it is acquired. Each custody
action (acquire, transfer, analyze, verify, release) is appended to a ledger
where every entry includes the hash of the entry before it. Editing,
reordering or deleting any past entry breaks the chain, and ``verify_chain``
reports exactly where.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64
CHUNK_SIZE = 1024 * 1024
ACTIONS = {"acquire", "transfer", "analyze", "verify", "release"}


def sha256_file(path: str | os.PathLike) -> str:
    """Hash a file in chunks so large disk images don't load into memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class EvidenceItem:
    evidence_id: str
    path: str
    sha256: str
    size: int
    description: str = ""
    acquired_at: str = field(default_factory=_now)


@dataclass
class CustodyEntry:
    seq: int
    evidence_id: str
    action: str
    handler: str
    timestamp: str
    notes: str
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "entry_hash"}
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass
class ChainProblem:
    seq: int
    reason: str


@dataclass
class IntegrityResult:
    evidence_id: str
    path: str
    expected: str
    actual: str | None

    @property
    def ok(self) -> bool:
        return self.actual == self.expected

    @property
    def status(self) -> str:
        if self.actual is None:
            return "MISSING"
        return "OK" if self.ok else "MODIFIED"


class CaseFile:
    """A case on disk: one JSON file holding evidence and the custody ledger."""

    def __init__(self, path: str | os.PathLike, case_id: str = "", examiner: str = ""):
        self.path = Path(path)
        self.case_id = case_id
        self.examiner = examiner
        self.evidence: dict[str, EvidenceItem] = {}
        self.ledger: list[CustodyEntry] = []

    @classmethod
    def load(cls, path: str | os.PathLike) -> "CaseFile":
        data = json.loads(Path(path).read_text())
        case = cls(path, data["case_id"], data.get("examiner", ""))
        case.evidence = {e["evidence_id"]: EvidenceItem(**e) for e in data["evidence"]}
        case.ledger = [CustodyEntry(**e) for e in data["ledger"]]
        return case

    def save(self) -> None:
        data = {
            "case_id": self.case_id,
            "examiner": self.examiner,
            "evidence": [asdict(e) for e in self.evidence.values()],
            "ledger": [asdict(e) for e in self.ledger],
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(self.path)

    def _append(self, evidence_id: str, action: str, handler: str, notes: str) -> CustodyEntry:
        if action not in ACTIONS:
            raise ValueError(f"unknown custody action: {action}")
        prev = self.ledger[-1].entry_hash if self.ledger else GENESIS_HASH
        entry = CustodyEntry(
            seq=len(self.ledger),
            evidence_id=evidence_id,
            action=action,
            handler=handler,
            timestamp=_now(),
            notes=notes,
            prev_hash=prev,
        )
        entry.entry_hash = entry.compute_hash()
        self.ledger.append(entry)
        return entry

    def acquire(self, path: str | os.PathLike, handler: str, description: str = "") -> EvidenceItem:
        path = Path(path)
        evidence_id = f"EV-{len(self.evidence) + 1:03d}"
        item = EvidenceItem(
            evidence_id=evidence_id,
            path=str(path.resolve()),
            sha256=sha256_file(path),
            size=path.stat().st_size,
            description=description,
        )
        self.evidence[evidence_id] = item
        self._append(evidence_id, "acquire", handler, f"sha256={item.sha256}")
        return item

    def record(self, evidence_id: str, action: str, handler: str, notes: str = "") -> CustodyEntry:
        if evidence_id not in self.evidence:
            raise KeyError(f"no evidence with id {evidence_id}")
        return self._append(evidence_id, action, handler, notes)

    def history(self, evidence_id: str) -> list[CustodyEntry]:
        return [e for e in self.ledger if e.evidence_id == evidence_id]

    def verify_chain(self) -> list[ChainProblem]:
        """Check that no ledger entry was edited, removed or reordered."""
        problems: list[ChainProblem] = []
        prev = GENESIS_HASH
        for index, entry in enumerate(self.ledger):
            if entry.seq != index:
                problems.append(ChainProblem(entry.seq, f"sequence gap: expected {index}"))
            if entry.prev_hash != prev:
                problems.append(ChainProblem(entry.seq, "previous-hash link broken"))
            if entry.compute_hash() != entry.entry_hash:
                problems.append(ChainProblem(entry.seq, "entry contents altered"))
            prev = entry.entry_hash
        return problems

    def verify_evidence(self, handler: str = "") -> list[IntegrityResult]:
        """Re-hash every evidence file and compare against the acquisition hash."""
        results = []
        for item in self.evidence.values():
            actual = sha256_file(item.path) if os.path.exists(item.path) else None
            result = IntegrityResult(item.evidence_id, item.path, item.sha256, actual)
            results.append(result)
            if handler:
                self._append(item.evidence_id, "verify", handler, f"result={result.status}")
        return results
