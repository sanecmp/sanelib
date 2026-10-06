"""Typed activity events and exact JSONL packet validation."""

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, TypeAdapter, model_validator

from ..exceptions import PayloadTooLargeError, ProtocolError
from ..utils.validation import (
    NonEmptyString,
    NonNegativeInt,
    decode_json_adapter,
    parse_json_adapter,
)
from .base import ProtocolModel

MAX_EVENTS_PER_PACKET = 5_000
MAX_EVENT_PACKET_SIZE = 6 * 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class EventType(StrEnum):
    """Supported user activity event types."""

    SESSION_START = "session_start"
    SESSION_END = "session_end"
    PRC_START = "prc_start"
    PRC_END = "prc_end"
    ENFORCEMENT_FAILED = "enforcement_failed"


class Actor(StrEnum):
    """Actors that may finish a session or application run."""

    USER = "user"
    SANEX = "sanex"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class EnforcementFailureReason(StrEnum):
    """Supported window enforcement failure reasons."""

    CLOSE_UNSUPPORTED = "close_unsupported"
    CLOSE_FAILED = "close_failed"
    CLOSE_TIMEOUT = "close_timeout"


class ObservationSource(StrEnum):
    """Supported application observation sources."""

    ATSPI = "atspi"


class SessionStartMeta(ProtocolModel):
    """Metadata recorded when a login session is first observed."""

    existing: bool


class EndMeta(ProtocolModel):
    """Metadata recorded when a session or application run ends."""

    actor: Actor


class ProcessStartMeta(ProtocolModel):
    """Metadata describing how an application run was observed."""

    observed_via: ObservationSource


class EmptyMeta(ProtocolModel):
    """Metadata for an event without additional attributes."""


class _Event(ProtocolModel):
    seq: NonNegativeInt
    type: EventType
    timestamp: NonNegativeInt


class _StartEvent(_Event):
    """Common run identity for session and application starts."""

    run_ident: NonNegativeInt

    @model_validator(mode="after")
    def validate_run_ident(self) -> Self:
        """Use the start event sequence as its run identity."""

        if self.run_ident != self.seq:
            raise ValueError("run_ident must equal seq for a start event")

        return self


class SessionStartEvent(_StartEvent):
    """A login session started or was already active at discovery."""

    type: Literal[EventType.SESSION_START]
    sess_ident: NonEmptyString
    meta: SessionStartMeta


class SessionEndEvent(_Event):
    """A previously reported login session ended."""

    type: Literal[EventType.SESSION_END]
    run_ident: NonNegativeInt
    duration: NonNegativeInt
    meta: EndMeta


class ProcessStartEvent(_StartEvent):
    """A user application run reached the reporting threshold."""

    type: Literal[EventType.PRC_START]
    prc_name: NonEmptyString
    exe: NonEmptyString
    meta: ProcessStartMeta

class ProcessEndEvent(_Event):
    """A previously reported user application run ended."""

    type: Literal[EventType.PRC_END]
    run_ident: NonNegativeInt
    duration: NonNegativeInt
    meta: EndMeta


class EnforcementFailedEvent(_Event):
    """Closing one matching window was unavailable or unsuccessful."""

    type: Literal[EventType.ENFORCEMENT_FAILED]
    rule_ident: NonNegativeInt
    wnd_ident: NonNegativeInt
    reason: EnforcementFailureReason
    meta: EmptyMeta


Event = Annotated[
    SessionStartEvent
    | SessionEndEvent
    | ProcessStartEvent
    | ProcessEndEvent
    | EnforcementFailedEvent,
    Field(discriminator="type"),
]
EVENT_ADAPTER = TypeAdapter(Event)


@dataclass(frozen=True, slots=True)
class ParsedEventPacket:
    """Validated events and identity derived from exact packet bytes."""

    events: tuple[Event, ...]
    sha256: str

    @property
    def first_seq(self) -> int:
        return self.events[0].seq

    @property
    def last_seq(self) -> int:
        return self.events[-1].seq


def parse_event(data: str | bytes | bytearray) -> Event:
    """Decode and validate one JSON event."""
    return parse_json_adapter(EVENT_ADAPTER, data)


def decode_event(value: object) -> Event:
    """Validate a JSON-compatible Python value as an event."""
    return decode_json_adapter(EVENT_ADAPTER, value)


def encode_event(event: Event) -> bytes:
    """Serialize one event as a compact UTF-8 JSONL record."""
    return EVENT_ADAPTER.dump_json(event) + b"\n"


def _ensure_event_packet_size(data: bytes) -> None:
    """Reject an event packet exceeding the shared byte limit."""

    if len(data) > MAX_EVENT_PACKET_SIZE:
        raise PayloadTooLargeError("$", "event packet exceeds 6 MiB")


def iterate_event_records(
    data: bytes,
    *,
    allow_empty: bool = False,
) -> Iterator[Event]:
    """Yield a bounded strictly increasing JSONL event sequence."""
    _ensure_event_packet_size(data)

    if not data:

        if allow_empty:
            return

        raise ProtocolError("$", "event packet must not be empty")

    if not data.endswith(b"\n"):
        raise ProtocolError("$", "event packet has an incomplete final record")

    previous_seq: int | None = None

    for index, line in enumerate(data.splitlines()):

        if index >= MAX_EVENTS_PER_PACKET:
            raise ProtocolError(
                "$",
                f"event packet exceeds {MAX_EVENTS_PER_PACKET} records",
            )

        try:
            event = parse_event(line)

        except ProtocolError as error:
            path = error.path.removeprefix("$")
            raise ProtocolError(f"$[{index}]{path}", error.detail) from error

        if previous_seq is not None and event.seq <= previous_seq:
            raise ProtocolError(
                f"$[{index}].seq",
                f"event seq {event.seq} must be greater than {previous_seq}",
            )

        previous_seq = event.seq
        yield event


def validate_event_packet_digest(data: bytes, expected_sha256: str) -> str:
    """Validate the lowercase SHA-256 identity of exact packet bytes."""

    if _SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise ProtocolError("$.sha256", "invalid event packet SHA-256")

    actual_sha256 = hashlib.sha256(data).hexdigest()

    if actual_sha256 != expected_sha256:
        raise ProtocolError("$.sha256", "event packet SHA-256 does not match its body")

    return actual_sha256


def parse_event_packet(data: bytes, expected_sha256: str) -> ParsedEventPacket:
    """Validate exact packet bytes, digest, record count and sequence order."""
    _ensure_event_packet_size(data)
    digest = validate_event_packet_digest(data, expected_sha256)
    events = tuple(iterate_event_records(data))
    return ParsedEventPacket(events=events, sha256=digest)
