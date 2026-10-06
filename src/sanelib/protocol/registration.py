"""Client registration wire models."""

from typing import Annotated, Self

from pydantic import Field, TypeAdapter, ValidationError, model_validator

from ..exceptions import ProtocolError
from ..utils.validation import parse_json_model, require_unique
from .account import DiscoveredAccount
from .base import ProtocolModel
from .config import Config

RegistrationCode = Annotated[
    str,
    Field(
        pattern=r"^[A-HJ-KM-NP-Z2-9]{4}-[A-HJ-KM-NP-Z2-9]{4}$",
        strict=True,
    ),
]
_registration_code_adapter = TypeAdapter(RegistrationCode)


def validate_registration_code(code: str) -> str:
    """Return a code conforming to the one canonical registration alphabet."""
    try:
        return _registration_code_adapter.validate_python(code, strict=True)

    except ValidationError as error:
        raise ProtocolError(
            "$.code",
            "registration code must have format ABCD-EFGH",
        ) from error


class RegistrationRequest(ProtocolModel):
    """Unauthenticated one-use registration request."""

    code: RegistrationCode
    hostname: Annotated[str, Field(min_length=1, max_length=253, strict=True)]
    csr: Annotated[str, Field(min_length=1, max_length=16_384, strict=True)]


class RegistrationIssueResponse(ProtocolModel):
    """CA and client certificate issued for a generated CSR."""

    ca: Annotated[str, Field(min_length=1, strict=True)]
    certificate: Annotated[str, Field(min_length=1, strict=True)]


class RegistrationConfirmRequest(ProtocolModel):
    """Authenticated data completing one registration."""

    version: Annotated[str, Field(min_length=1, max_length=64, strict=True)]
    accounts: tuple[DiscoveredAccount, ...]

    @model_validator(mode="after")
    def validate_accounts(self) -> Self:
        """Require one entry for each reported UID."""
        require_unique((account.uid for account in self.accounts), "account UID")
        return self


class RegistrationConfirmResponse(ProtocolModel):
    """Initial complete sanex configuration wrapper."""

    config: Config


def parse_registration_request(
    data: str | bytes | bytearray,
) -> RegistrationRequest:
    """Decode a strict registration request."""
    return parse_json_model(RegistrationRequest, data)


def parse_registration_issue_response(
    data: str | bytes | bytearray,
) -> RegistrationIssueResponse:
    """Decode a strict certificate-issue response."""
    return parse_json_model(RegistrationIssueResponse, data)


def parse_registration_confirm_request(
    data: str | bytes | bytearray,
) -> RegistrationConfirmRequest:
    """Decode a strict registration-confirmation request."""
    return parse_json_model(RegistrationConfirmRequest, data)


def parse_registration_confirm_response(
    data: str | bytes | bytearray,
) -> RegistrationConfirmResponse:
    """Decode a strict registration-confirmation response."""
    return parse_json_model(RegistrationConfirmResponse, data)


def encode_registration_message(message: ProtocolModel) -> bytes:
    """Serialize a validated registration message as compact UTF-8 JSON."""
    try:
        return message.model_dump_json().encode()

    except (TypeError, ValueError) as error:
        raise ProtocolError("$", f"unable to encode registration message: {error}") from error
