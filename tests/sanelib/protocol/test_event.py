"""Tests for the shared event and JSONL packet contract."""

import hashlib
import json

import pytest
from pydantic import ValidationError

from sanelib.exceptions import PayloadTooLargeError, ProtocolError
from sanelib.protocol import (
    MAX_EVENT_PACKET_SIZE,
    Actor,
    ApplicationIdentity,
    EmptyMeta,
    EnforcementFailedEvent,
    EventType,
    ProcessEndEvent,
    ProcessStartEvent,
    ProcessUpdateEvent,
    SessionEndEvent,
    SessionStartEvent,
    UsageInterval,
    decode_event,
    encode_event,
    parse_event,
    parse_event_packet,
)


def test_application_identity_round_trips_without_overwriting_process_fields(event_records: tuple[bytes, ...]) -> None:
    payload = json.loads(event_records[2])
    payload["application"] = {"ident": "steam:client", "name": "Steam"}

    event = decode_event(payload)
    restored = parse_event(encode_event(event))

    assert restored.application.ident == "steam:client"
    assert restored.application.name == "Steam"
    assert restored.prc_name == payload["prc_name"]
    assert restored.exe == payload["exe"]


@pytest.mark.parametrize("source", ["atspi", "ewmh", "process"])
def test_application_observation_sources_round_trip(event_records: tuple[bytes, ...], source: str) -> None:
    payload = json.loads(event_records[2])
    payload["meta"]["observed_via"] = source

    restored = parse_event(encode_event(decode_event(payload)))

    assert restored.meta.observed_via == source


def test_process_update_round_trips_without_becoming_another_start() -> None:
    event = ProcessUpdateEvent(
        seq=123, type=EventType.PRC_UPDATE, timestamp=1_790_845_600, run_ident=121,
        application=ApplicationIdentity(ident="steam:game:440", name="Team Fortress 2"), meta=EmptyMeta(),
    )
    content = encode_event(event)

    packet = parse_event_packet(content, hashlib.sha256(content).hexdigest())

    assert packet.events == (event,)
    assert parse_event(content) == event
    assert event.run_ident == 121
    assert "duration" not in json.loads(content)


@pytest.mark.parametrize(("field", "value", "message"), [
    ("run_ident", 123, "run_ident must precede seq"),
    ("run_ident", 124, "run_ident must precede seq"),
    ("application", None, "application"),
    ("application", {"ident": "steam:game:440", "name": ""}, "application.name"),
    ("duration", 1, "Extra inputs are not permitted"),
])
def test_process_update_rejects_invalid_identity_or_run_fields(field: str, value: object, message: str) -> None:
    payload = {
        "seq": 123, "type": "prc_update", "timestamp": 1_790_845_600, "run_ident": 121,
        "application": {"ident": "steam:game:440", "name": "Team Fortress 2"}, "meta": {},
    }
    payload[field] = value

    with pytest.raises(ProtocolError, match=message):
        decode_event(payload)


@pytest.mark.parametrize("application", [
    {"ident": "", "name": "Steam"}, {"ident": "x" * 4097, "name": "Steam"},
    {"ident": "steam:client", "name": ""}, {"ident": "steam:client", "name": "Steam", "cmdline": "secret"},
])
def test_rejects_invalid_application_metadata(event_records: tuple[bytes, ...], application: dict[str, str]) -> None:
    payload = json.loads(event_records[2])
    payload["application"] = application

    with pytest.raises(ProtocolError, match="application"):
        decode_event(payload)


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


@pytest.mark.parametrize("record_index", [1, 3], ids=["session", "process"])
def test_completed_run_intervals_round_trip_separately_from_metadata(
    event_records: tuple[bytes, ...], record_index: int,
) -> None:
    payload = json.loads(event_records[record_index])
    payload["intervals"] = [
        {"timestamp": payload["timestamp"] - 86_400, "duration": 1_000},
        {"timestamp": payload["timestamp"], "duration": payload["duration"] - 1_000},
    ]
    event = decode_event(payload)

    serialized = encode_event(event)
    packet = parse_event_packet(serialized, hashlib.sha256(serialized).hexdigest())

    assert packet.events == (event,)
    assert json.loads(serialized)["intervals"] == payload["intervals"]
    assert event.intervals is not None
    assert all(isinstance(interval, UsageInterval) for interval in event.intervals)
    assert sum(interval.duration for interval in event.intervals) == event.duration
    assert json.loads(serialized)["meta"] == {"actor": "user"}


@pytest.mark.parametrize("record_index", [1, 3], ids=["session", "process"])
@pytest.mark.parametrize("duration", [0, 20])
def test_completed_run_without_intervals_retains_unknown_distribution(
    event_records: tuple[bytes, ...], record_index: int, duration: int,
) -> None:
    payload = json.loads(event_records[record_index])
    del payload["intervals"]
    payload["duration"] = duration

    event = parse_event(encode_event(decode_event(payload)))

    assert event.intervals is None
    assert event.duration == duration


@pytest.mark.parametrize("record_index", [1, 3], ids=["session", "process"])
def test_completed_run_with_known_zero_duration_has_empty_intervals(
    event_records: tuple[bytes, ...], record_index: int,
) -> None:
    payload = json.loads(event_records[record_index])
    payload.update(duration=0, intervals=[])

    event = parse_event(encode_event(decode_event(payload)))

    assert event.intervals == ()
    assert event.duration == 0


@pytest.mark.parametrize(
    ("interval", "message"),
    [
        ({"timestamp": 100, "duration": 0}, "greater than 0"),
        ({"timestamp": 100, "duration": -1}, "greater than 0"),
        ({"timestamp": 100, "duration": True}, "valid integer"),
        ({"timestamp": 100, "duration": "20"}, "valid integer"),
        ({"timestamp": -1, "duration": 20}, "greater than or equal to 0"),
        ({"timestamp": True, "duration": 20}, "valid integer"),
        ({"timestamp": 19, "duration": 20}, "must not start before the Unix epoch"),
        ({"timestamp": 100, "duration": 20, "extra": True}, "Extra inputs are not permitted"),
    ],
)
def test_completed_run_rejects_invalid_interval_fields(interval: dict[str, object], message: str) -> None:
    payload = {
        "seq": 2, "type": "session_end", "timestamp": 100, "run_ident": 1,
        "duration": 20, "intervals": [interval], "meta": {"actor": "user"},
    }

    with pytest.raises(ProtocolError, match=message):
        decode_event(payload)


@pytest.mark.parametrize("event_type", ["session_end", "prc_end"])
@pytest.mark.parametrize("duration", [19, 21])
def test_completed_run_requires_intervals_to_account_for_the_entire_duration(event_type: str, duration: int) -> None:
    payload = {
        "seq": 2, "type": event_type, "timestamp": 100, "run_ident": 1, "duration": duration,
        "intervals": [{"timestamp": 100, "duration": 20}], "meta": {"actor": "user"},
    }

    with pytest.raises(ProtocolError, match="interval durations must sum to duration"):
        decode_event(payload)


def test_completed_run_preserves_interval_order_when_the_wall_clock_changes() -> None:
    payload = {
        "seq": 2, "type": "session_end", "timestamp": 100, "run_ident": 1, "duration": 30,
        "intervals": [{"timestamp": 1_000, "duration": 10}, {"timestamp": 500, "duration": 20}],
        "meta": {"actor": "user"},
    }

    event = decode_event(payload)

    assert event.intervals == (UsageInterval(timestamp=1_000, duration=10), UsageInterval(timestamp=500, duration=20))
    assert event.duration == 30


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
