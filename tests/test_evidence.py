import hashlib
import json

import pytest

from chronicle.evidence import GENESIS_HASH, CaseFile, sha256_file


@pytest.fixture
def case(tmp_path):
    artifact = tmp_path / "disk.img"
    artifact.write_bytes(b"evidence bytes" * 1000)
    case = CaseFile(tmp_path / "case.json", "IR-TEST-001", "examiner")
    case.acquire(artifact, handler="alice", description="test image")
    case.record("EV-001", "transfer", "alice", "to locker")
    case.record("EV-001", "analyze", "bob", "timeline built")
    case.save()
    return case, artifact


def test_sha256_matches_hashlib(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(b"x" * 3_000_000)
    assert sha256_file(path) == hashlib.sha256(b"x" * 3_000_000).hexdigest()


def test_acquire_records_hash_and_first_entry(case):
    case, artifact = case
    item = case.evidence["EV-001"]
    assert item.sha256 == sha256_file(artifact)
    assert case.ledger[0].action == "acquire"
    assert case.ledger[0].prev_hash == GENESIS_HASH


def test_chain_is_intact_after_round_trip(case):
    case, _ = case
    loaded = CaseFile.load(case.path)
    assert loaded.verify_chain() == []
    assert [e.action for e in loaded.history("EV-001")] == ["acquire", "transfer", "analyze"]


def test_editing_an_entry_breaks_the_chain(case):
    case, _ = case
    data = json.loads(case.path.read_text())
    data["ledger"][1]["handler"] = "mallory"
    case.path.write_text(json.dumps(data))
    problems = CaseFile.load(case.path).verify_chain()
    assert any(p.seq == 1 and "altered" in p.reason for p in problems)


def test_deleting_an_entry_breaks_the_chain(case):
    case, _ = case
    data = json.loads(case.path.read_text())
    del data["ledger"][1]
    case.path.write_text(json.dumps(data))
    reasons = [p.reason for p in CaseFile.load(case.path).verify_chain()]
    assert any("sequence gap" in r for r in reasons)
    assert any("link broken" in r for r in reasons)


def test_modified_evidence_is_detected(case):
    case, artifact = case
    artifact.write_bytes(b"tampered")
    [result] = case.verify_evidence()
    assert result.status == "MODIFIED"


def test_missing_evidence_is_detected(case):
    case, artifact = case
    artifact.unlink()
    [result] = case.verify_evidence()
    assert result.status == "MISSING"


def test_verification_is_logged_when_handler_given(case):
    case, _ = case
    case.verify_evidence(handler="carol")
    assert case.ledger[-1].action == "verify"
    assert case.ledger[-1].notes == "result=OK"
    assert case.verify_chain() == []


def test_unknown_action_and_evidence_rejected(case):
    case, _ = case
    with pytest.raises(ValueError):
        case.record("EV-001", "destroy", "alice")
    with pytest.raises(KeyError):
        case.record("EV-999", "transfer", "alice")
