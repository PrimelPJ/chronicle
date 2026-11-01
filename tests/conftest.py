from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def samples() -> Path:
    return SAMPLES


def read_lines(path: Path) -> list[str]:
    return path.read_text().splitlines()
