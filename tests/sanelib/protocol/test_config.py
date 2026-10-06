"""Tests for the shared configuration contract."""

from typing import Any

import pytest

from sanelib.exceptions import ProtocolError
from sanelib.protocol import decode_config, encode_config, parse_config


def test_configuration_round_trip(config_payload: dict[str, Any]) -> None:
    config = decode_config(config_payload)

    assert parse_config(encode_config(config)) == config
    assert config.accounts[0].limits is not None
    assert config.ignored_prcs == ("nautilus",)


def test_configuration_requires_ignored_processes(
    config_payload: dict[str, Any],
) -> None:
    config_payload.pop("ignored_prcs")

    with pytest.raises(ProtocolError, match=r"\$\.ignored_prcs: Field required"):
        decode_config(config_payload)


def test_configuration_accepts_explicit_empty_ignored_processes(
    config_payload: dict[str, Any],
) -> None:
    config_payload["ignored_prcs"] = []

    config = decode_config(config_payload)

    assert config.ignored_prcs == ()


@pytest.mark.parametrize(
    "names",
    [
        pytest.param(["nautilus", "nautilus"], id="duplicate-process-name"),
        pytest.param(["a-process-name-too-long"], id="long-process-name"),
    ],
)
def test_configuration_rejects_invalid_ignored_process_names(
    config_payload: dict[str, Any],
    names: list[str],
) -> None:
    config_payload["ignored_prcs"] = names

    with pytest.raises(ProtocolError, match=r"ignored_prcs|ignored process name"):
        decode_config(config_payload)


def test_configuration_validates_cross_references(
    config_payload: dict[str, Any],
) -> None:
    limits = config_payload["accounts"][0]["limits"]
    limits["ranges"][0]["session_rule_ident"] = 999

    with pytest.raises(ProtocolError, match="references unknown SessionRule 999"):
        decode_config(config_payload)


def test_configuration_rejects_ambiguous_json() -> None:

    with pytest.raises(ProtocolError, match="duplicate object key 'ident'"):
        parse_config("{\"ident\":1,\"ident\":2}")
