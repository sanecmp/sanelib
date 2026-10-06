"""Tests for the shared synchronization contract."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from sanelib.exceptions import ProtocolError
from sanelib.protocol import (
    UpdateCommandPayload,
    encode_sync_request,
    encode_sync_response,
    parse_sync_request,
    parse_sync_response,
)


def test_sync_messages_round_trip(sync_payload: dict[str, Any]) -> None:
    request = parse_sync_request(json.dumps(sync_payload["request"]))
    response = parse_sync_response(json.dumps(sync_payload["response"]))

    assert parse_sync_request(encode_sync_request(request)) == request
    assert parse_sync_response(encode_sync_response(response)) == response


def test_sync_omits_unavailable_account_snapshot(
    sync_payload: dict[str, Any],
) -> None:
    sync_payload["request"].pop("accounts")

    request = parse_sync_request(json.dumps(sync_payload["request"]))

    assert "accounts" not in json.loads(encode_sync_request(request))

    sync_payload["request"]["accounts"] = None

    with pytest.raises(ProtocolError, match="omitted instead of null"):
        parse_sync_request(json.dumps(sync_payload["request"]))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        pytest.param("unexpected", True, "Extra inputs are not permitted", id="unknown-field"),
        pytest.param(
            "command_results",
            [{"ident": 91, "status": "failed", "error": "x" * 1_025}],
            "between 1 and 1024",
            id="long-command-error",
        ),
    ],
)
def test_sync_request_rejects_invalid_fields(
    sync_payload: dict[str, Any],
    field: str,
    value: object,
    message: str,
) -> None:
    payload = sync_payload["request"]
    payload[field] = value

    with pytest.raises(ProtocolError, match=message):
        parse_sync_request(json.dumps(payload))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        pytest.param("version", "not a version", "version must conform to PEP 440", id="invalid-version"),
        pytest.param(
            "index_url",
            "http://packages.example.test/simple",
            "index_url must be an absolute HTTPS URL",
            id="insecure-index",
        ),
        pytest.param(
            "index_url",
            "https://user@packages.example.test/simple",
            "without credentials or fragment",
            id="index-credentials",
        ),
        pytest.param(
            "index_url",
            "https://packages.example.test/simple#fragment",
            "without credentials or fragment",
            id="index-fragment",
        ),
    ],
)
def test_update_command_payload_rejects_unsafe_values(
    field: str,
    value: str,
    message: str,
) -> None:
    payload = {
        "version": "0.3.0",
        "index_url": "https://packages.example.test/simple",
    }
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        UpdateCommandPayload.model_validate(payload)


def test_update_command_payload_accepts_release_and_https_index() -> None:
    payload = UpdateCommandPayload(
        version="0.3.0rc1",
        index_url="https://packages.example.test/simple",
    )

    assert payload.model_dump() == {
        "version": "0.3.0rc1",
        "index_url": "https://packages.example.test/simple",
    }
