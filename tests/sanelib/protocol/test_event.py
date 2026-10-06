"""Tests for the shared event and JSONL packet contract."""

import hashlib
import json

import pytest
from pydantic import ValidationError

from sanelib.exceptions import PayloadTooLargeError, ProtocolError
from sanelib.protocol import (
    MAX_EVENT_PACKET_SIZE,
    Actor,
    EnforcementFailedEvent,
    EventType,
    ProcessEndEvent,
    ProcessStartEvent,
    SessionEndEvent,
    SessionStartEvent,
    decode_event,
    encode_event,
    parse_event,
    parse_event_packet,
)


def test_packet_rejects_body_larger_than_six_mib() -> None:
    content = b"x" * (MAX_EVENT_PACKET_SIZE + 1)

    with pytest.raises(PayloadTooLargeError, match="exceeds 6 MiB"):
        parse_event_packet(content, "0" * 64)


def test_event_types_round_trip_as_exact_jsonl(
    event_records: tuple[bytes, ...],
) -> None:
    expected_types = (
        SessionStartEvent,
        SessionEndEvent,
        ProcessStartEvent,
        ProcessEndEvent,
        EnforcementFailedEvent,
    )
    events = tuple(parse_event(record) for record in event_records)

    assert tuple(type(event) for event in events) == expected_types
    assert tuple(encode_event(event) for event in events) == tuple(
        record + b"\n" for record in event_records
    )
    assert decode_event(json.loads(event_records[0])) == events[0]
    assert events[0].type is EventType.SESSION_START
    assert events[1].meta.actor is Actor.USER

    with pytest.raises(ValidationError, match="Instance is frozen"):
        events[0].seq = 1


@pytest.mark.parametrize(
    "record_index",
    [
        pytest.param(0, id="session-start"),
        pytest.param(2, id="process-start"),
    ],
)
def test_start_event_requires_sequence_as_run_identity(
    event_records: tuple[bytes, ...],
    record_index: int,
) -> None:
    payload = json.loads(event_records[record_index])
    payload["run_ident"] -= 1

    with pytest.raises(ProtocolError, match="run_ident must equal seq"):
        decode_event(payload)


@pytest.mark.parametrize(
    ("record_index", "field", "value", "message"),
    [
        pytest.param(1, "actor", "other", "Input should be", id="unknown-actor"),
        pytest.param(4, "reason", "kill_failed", "Input should be", id="unknown-failure-reason"),
        pytest.param(0, "seq", True, "valid integer", id="boolean-sequence"),
        pytest.param(0, "type", "unknown", "Input tag 'unknown'", id="unknown-event-type"),
    ],
)
def test_event_contract_rejects_invalid_values(
    event_records: tuple[bytes, ...],
    record_index: int,
    field: str,
    value: object,
    message: str,
) -> None:
    payload = json.loads(event_records[record_index])
    target = payload["meta"] if field == "actor" else payload
    target[field] = value

    with pytest.raises(ProtocolError, match=message):
        decode_event(payload)


def test_packet_validates_exact_digest_and_sequence(
    event_records: tuple[bytes, ...],
) -> None:
    ordered = sorted(
        (parse_event(record) for record in event_records),
        key=lambda event: event.seq,
    )
    content = b"".join(encode_event(event) for event in ordered)
    digest = hashlib.sha256(content).hexdigest()

    packet = parse_event_packet(content, digest)

    assert packet.events == tuple(ordered)
    assert packet.first_seq == ordered[0].seq
    assert packet.last_seq == ordered[-1].seq
    assert packet.sha256 == digest


@pytest.mark.parametrize(
    ("content", "digest", "message"),
    [
        pytest.param(b"", hashlib.sha256(b"").hexdigest(), "must not be empty", id="empty-packet"),
        pytest.param(b"{}", hashlib.sha256(b"{}").hexdigest(), "incomplete final record", id="incomplete-record"),
        pytest.param(b"{}\n", "0" * 64, "does not match its body", id="digest-mismatch"),
        pytest.param(b"{}\n", "invalid", "invalid event packet SHA-256", id="invalid-digest"),
    ],
)
def test_packet_rejects_invalid_envelope(
    content: bytes,
    digest: str,
    message: str,
) -> None:

    with pytest.raises(ProtocolError, match=message):
        parse_event_packet(content, digest)


def test_packet_rejects_non_increasing_sequences(
    event_records: tuple[bytes, ...],
) -> None:
    record = event_records[0] + b"\n"
    content = record + record
    digest = hashlib.sha256(content).hexdigest()

    with pytest.raises(ProtocolError, match="must be greater"):
        parse_event_packet(content, digest)
