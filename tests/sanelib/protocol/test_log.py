"""Tests for the shared technical-log contract."""

import pytest

from sanelib.exceptions import PayloadTooLargeError, ProtocolError
from sanelib.protocol import MAX_LOG_TAIL_SIZE, decode_log_tail


def test_log_tail_accepts_exact_limit() -> None:
    content = b"x" * MAX_LOG_TAIL_SIZE

    assert decode_log_tail(content) == content.decode()


@pytest.mark.parametrize(
    ("content", "error", "message"),
    [
        pytest.param(b"x" * (MAX_LOG_TAIL_SIZE + 1), PayloadTooLargeError, "exceeds 64 KiB", id="too-large"),
        pytest.param(b"invalid: \xff", ProtocolError, "not valid UTF-8", id="invalid-utf8"),
    ],
)
def test_log_tail_rejects_invalid_payloads(
    content: bytes,
    error: type[ProtocolError],
    message: str,
) -> None:

    with pytest.raises(error, match=message):
        decode_log_tail(content)
