"""Authenticated control-exchange wire models."""

import json
from enum import StrEnum
from typing import Annotated, Self
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version
from pydantic import Field, JsonValue, field_validator, model_validator

from ..exceptions import ProtocolError
from ..utils.validation import NonNegativeInt, parse_json_model, require_unique
from .account import DiscoveredAccount
from .base import ProtocolModel
from .config import Config


class CommandStatus(StrEnum):
    """Terminal command states reported to sanea."""

    DONE = "done"
    FAILED = "failed"


class CommandResult(ProtocolModel):
    """One durable terminal command result awaiting acknowledgement."""

    ident: NonNegativeInt
    status: CommandStatus
    error: str | None

    @field_validator("error")
    @classmethod
    def validate_error(cls, value: str | None) -> str | None:
        """Bound a non-empty client error description."""

        if value is not None and (not value or len(value) > 1_024):
            raise ValueError("error must contain between 1 and 1024 characters")

        return value


class Command(ProtocolModel):
    """One sanea command, retaining payloads for unknown command types."""

    ident: NonNegativeInt
    type: Annotated[str, Field(min_length=1, max_length=64, strict=True)]
    payload: dict[str, JsonValue]


class UpdateCommandPayload(ProtocolModel):
    """Strict payload shared by sanea and the sanex update handler."""

    version: Annotated[str, Field(min_length=1, strict=True)]
    index_url: Annotated[str, Field(min_length=1, strict=True)]

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        """Require a valid PEP 440 release identifier."""
        try:
            Version(value)

        except InvalidVersion as error:
            raise ValueError("version must conform to PEP 440") from error

        return value

    @field_validator("index_url")
    @classmethod
    def validate_index_url(cls, value: str) -> str:
        """Require a credential-free absolute HTTPS package-index URL."""

        if any(character.isspace() for character in value):
            raise ValueError("index_url must not contain whitespace")

        try:
            parsed = urlsplit(value)
            _ = parsed.port

        except ValueError as error:
            raise ValueError("index_url must be a valid URL") from error

        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError(
                "index_url must be an absolute HTTPS URL without "
                "credentials or fragment"
            )

        return value


class SyncRequest(ProtocolModel):
    """Authenticated control request sent once per synchronization cycle."""

    hostname: Annotated[str, Field(min_length=1, max_length=253, strict=True)]
    version: Annotated[str, Field(min_length=1, max_length=64, strict=True)]
    config_ident: NonNegativeInt | None
    accounts: tuple[DiscoveredAccount, ...] | None = None
    command_results: tuple[CommandResult, ...]

    @model_validator(mode="after")
    def validate_identities(self) -> Self:
        """Require unique account and command identities."""

        if self.accounts is not None:
            require_unique(
                (account.uid for account in self.accounts),
                "account UID",
            )

        require_unique(
            (result.ident for result in self.command_results),
            "command result ident",
        )
        return self


class SyncResponse(ProtocolModel):
    """Validated control response returned by sanea."""

    config: Config | None
    commands: tuple[Command, ...]

    @model_validator(mode="after")
    def validate_commands(self) -> Self:
        """Require unique command identities."""
        require_unique((command.ident for command in self.commands), "command ident")
        return self


def parse_sync_request(data: str | bytes | bytearray) -> SyncRequest:
    """Decode and strictly validate one control request."""
    request = parse_json_model(SyncRequest, data)

    try:
        decoded = json.loads(data)

    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProtocolError("$", f"invalid JSON: {error}") from error

    if "accounts" in decoded and decoded["accounts"] is None:
        raise ProtocolError("$.accounts", "accounts must be omitted instead of null")

    return request


def parse_sync_response(data: str | bytes | bytearray) -> SyncResponse:
    """Decode and strictly validate one control response."""
    return parse_json_model(SyncResponse, data)


def encode_sync_request(request: SyncRequest) -> bytes:
    """Serialize a request while omitting an unavailable account snapshot."""
    exclude = {"accounts"} if request.accounts is None else None
    return request.model_dump_json(exclude=exclude).encode()


def encode_sync_response(response: SyncResponse) -> bytes:
    """Serialize a validated control response as compact UTF-8 JSON."""
    return response.model_dump_json().encode()
