"""Technical-log wire constraints."""

from ..exceptions import PayloadTooLargeError, ProtocolError

MAX_LOG_TAIL_SIZE = 65_536


def decode_log_tail(data: bytes) -> str:
    """Validate and decode one bounded technical-log snapshot."""

    if len(data) > MAX_LOG_TAIL_SIZE:
        raise PayloadTooLargeError("$", "technical log exceeds 64 KiB")

    try:
        return data.decode("utf-8")

    except UnicodeDecodeError as error:
        raise ProtocolError("$", "technical log is not valid UTF-8") from error
