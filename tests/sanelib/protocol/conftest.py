"""Data-backed fixtures for shared protocol tests."""

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def config_payload(datafix_dir: Path) -> dict[str, Any]:
    return json.loads((datafix_dir / "config.json").read_text())


@pytest.fixture
def sync_payload(datafix_dir: Path) -> dict[str, Any]:
    return json.loads((datafix_dir / "sync.json").read_text())


@pytest.fixture
def registration_payload(datafix_dir: Path) -> dict[str, Any]:
    return json.loads((datafix_dir / "registration.json").read_text())


@pytest.fixture
def event_records(datafix_dir: Path) -> tuple[bytes, ...]:
    return tuple((datafix_dir / "events.jsonl").read_bytes().splitlines())
