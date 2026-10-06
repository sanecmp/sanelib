"""Immutable sanex configuration wire models."""

import re
from enum import StrEnum
from itertools import pairwise
from typing import Annotated, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, field_validator, model_validator

from ..utils.validation import (
    NonEmptyString,
    NonNegativeInt,
    decode_json_model,
    parse_json_model,
    require_unique,
)
from .base import ProtocolModel


class MatchType(StrEnum):
    """Supported application recognition methods."""

    EXACT = "exact"
    CONTAINS = "contains"
    REGEX = "regex"


class AppRule(ProtocolModel):
    """Limits and recognition conditions for one user application."""

    ident: NonNegativeInt
    name: NonEmptyString
    apply: bool
    max_launches: NonNegativeInt | None
    max_time: NonNegativeInt | None
    prc_name: NonEmptyString | None
    prc_name_match: MatchType | None
    exe: NonEmptyString | None
    exe_match: MatchType | None
    wnd_title: NonEmptyString | None
    wnd_title_match: MatchType | None

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        """Validate limits and recognition condition pairs."""

        if self.max_launches is None and self.max_time is None:
            raise ValueError("at least one limit is required")

        conditions = (
            ("prc_name", self.prc_name, self.prc_name_match),
            ("exe", self.exe, self.exe_match),
            ("wnd_title", self.wnd_title, self.wnd_title_match),
        )

        if not any(condition is not None for _, condition, _ in conditions):
            raise ValueError("at least one recognition condition is required")

        for name, condition, match_type in conditions:

            if condition is None and match_type is not None:
                raise ValueError(f"{name}_match must be null when {name} is null")

            if condition is not None and match_type is None:
                raise ValueError(f"{name}_match is required when {name} is set")

            if condition is not None and match_type is MatchType.REGEX:
                try:
                    re.compile(condition)

                except re.error as error:
                    raise ValueError(
                        f"{name} is not a valid regular expression: {error}"
                    ) from error

        return self


class SessionRule(ProtocolModel):
    """Session and application limits used by one or more ranges."""

    ident: NonNegativeInt
    apply: bool
    max_sessions: NonNegativeInt | None
    max_duration: NonNegativeInt | None
    break_duration: NonNegativeInt
    app_rules: tuple[AppRule, ...]


class Range(ProtocolModel):
    """One allowed half-open interval within a weekday."""

    ident: NonNegativeInt
    apply: bool
    weekday: Annotated[int, Field(ge=0, le=6, strict=True)]
    since: Annotated[int, Field(ge=0, le=1_439, strict=True)]
    till: Annotated[int, Field(ge=1, le=1_440, strict=True)]
    session_rule_ident: NonNegativeInt

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        """Require a non-empty interval contained in one day."""

        if self.since >= self.till:
            raise ValueError("must satisfy since < till")

        return self


class Limits(ProtocolModel):
    """Complete schedule and its reusable session rules."""

    ranges: tuple[Range, ...]
    session_rules: tuple[SessionRule, ...]

    @model_validator(mode="after")
    def validate_relations(self) -> Self:
        """Validate identities, references and schedule intersections."""
        require_unique((entry.ident for entry in self.ranges), "Range ident")
        require_unique(
            (entry.ident for entry in self.session_rules),
            "SessionRule ident",
        )
        require_unique(
            (
                app_rule.ident
                for session_rule in self.session_rules
                for app_rule in session_rule.app_rules
            ),
            "AppRule ident",
        )
        known_rule_idents = {entry.ident for entry in self.session_rules}

        for entry in self.ranges:

            if entry.session_rule_ident not in known_rule_idents:
                raise ValueError(
                    f"Range {entry.ident} references unknown SessionRule "
                    f"{entry.session_rule_ident}"
                )

        _validate_non_overlapping_ranges(self.ranges)
        return self


class Account(ProtocolModel):
    """Configuration of one local operating-system account."""

    uid: NonNegativeInt
    collect: bool
    apply: bool
    limits: Limits | None

    @model_validator(mode="after")
    def validate_flags(self) -> Self:
        """Validate dependencies between observation and enforcement."""

        if self.apply and not self.collect:
            raise ValueError("apply=true requires collect=true")

        if self.apply and self.limits is None:
            raise ValueError("apply=true requires limits")

        return self


class Config(ProtocolModel):
    """Complete immutable configuration snapshot for one computer."""

    ident: NonNegativeInt
    timezone: NonEmptyString
    sync_interval: Annotated[int, Field(ge=10, le=86_400, strict=True)]
    discovery_interval: Annotated[int, Field(ge=1, strict=True)]
    walk_interval: Annotated[int, Field(ge=1, strict=True)]
    save_interval: Annotated[int, Field(ge=1, le=300, strict=True)]
    min_prc_duration: Annotated[int, Field(ge=0, le=60, strict=True)]
    ignored_prcs: tuple[
        Annotated[str, Field(min_length=1, max_length=15)], ...
    ]
    accounts: tuple[Account, ...]

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        """Require an available IANA timezone name."""
        try:
            ZoneInfo(value)

        except (ValueError, ZoneInfoNotFoundError) as error:
            raise ValueError("unknown IANA timezone") from error

        return value

    @model_validator(mode="after")
    def validate_intervals_and_accounts(self) -> Self:
        """Validate root intervals and account identities."""

        if self.discovery_interval > self.sync_interval:
            raise ValueError("discovery_interval must not exceed sync_interval")

        if self.walk_interval > self.save_interval:
            raise ValueError("walk_interval must not exceed save_interval")

        require_unique(self.ignored_prcs, "ignored process name")
        require_unique((account.uid for account in self.accounts), "Account uid")
        return self


def parse_config(data: str | bytes | bytearray) -> Config:
    """Decode and validate a complete JSON configuration snapshot."""
    return parse_json_model(Config, data)


def decode_config(value: object) -> Config:
    """Validate a JSON-compatible configuration value."""
    return decode_json_model(Config, value)


def encode_config(config: Config) -> bytes:
    """Serialize a validated configuration as compact UTF-8 JSON."""
    return config.model_dump_json().encode()


def _validate_non_overlapping_ranges(ranges: tuple[Range, ...]) -> None:

    for weekday in range(7):
        applied = sorted(
            (entry for entry in ranges if entry.apply and entry.weekday == weekday),
            key=lambda entry: entry.since,
        )

        for previous, current in pairwise(applied):

            if current.since < previous.till:
                raise ValueError(
                    f"Range {current.ident} overlaps Range {previous.ident}"
                )
