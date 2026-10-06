"""Tests for the shared local-account contract."""

import pytest
from pydantic import ValidationError

from sanelib.protocol import DiscoveredAccount


def test_discovered_account_preserves_wire_fields() -> None:
    account = DiscoveredAccount(uid=1001, login="child", name="Иван")

    assert account.model_dump() == {
        "uid": 1001,
        "login": "child",
        "name": "Иван",
    }


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        pytest.param("uid", True, "Input should be a valid integer", id="boolean-uid"),
        pytest.param("login", "x" * 257, "String should have at most 256 characters", id="long-login"),
    ],
)
def test_discovered_account_rejects_invalid_values(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = {"uid": 1001, "login": "child", "name": "Иван"}
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        DiscoveredAccount.model_validate(payload)
