"""Tests for the shared registration contract."""

import json
from typing import Any

import pytest

from sanelib.exceptions import ProtocolError
from sanelib.protocol import (
    encode_registration_message,
    parse_registration_confirm_request,
    parse_registration_issue_response,
    parse_registration_request,
    validate_registration_code,
)


def test_registration_messages_round_trip(
    registration_payload: dict[str, Any],
) -> None:
    request = parse_registration_request(json.dumps(registration_payload["request"]))
    issue = parse_registration_issue_response(
        json.dumps(registration_payload["issue_response"])
    )
    confirmation = parse_registration_confirm_request(
        json.dumps(registration_payload["confirm_request"])
    )

    assert parse_registration_request(encode_registration_message(request)) == request
    assert parse_registration_issue_response(encode_registration_message(issue)) == issue
    assert (
        parse_registration_confirm_request(encode_registration_message(confirmation))
        == confirmation
    )


def test_registration_code_uses_one_canonical_alphabet(
    registration_payload: dict[str, Any],
) -> None:
    registration_payload["request"]["code"] = "ABCL-EFGH"

    with pytest.raises(ProtocolError, match="String should match pattern"):
        parse_registration_request(json.dumps(registration_payload["request"]))

    with pytest.raises(ProtocolError, match="format ABCD-EFGH"):
        validate_registration_code("ABCL-EFGH")
