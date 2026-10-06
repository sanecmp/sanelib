"""Shared library exception hierarchy."""


class SanelibException(Exception):
    """Base class for expected sanelib failures."""


class ProtocolError(SanelibException):
    """A value does not conform to the shared wire protocol."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.detail = message
        super().__init__(f"{path}: {message}")


class PayloadTooLargeError(ProtocolError):
    """A bounded wire payload exceeds its documented size."""
