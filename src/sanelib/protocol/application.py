"""Application identity independent of executable and process lifetime."""

from typing import Annotated

from pydantic import Field

from .base import ProtocolModel


ApplicationId = Annotated[str, Field(min_length=1, max_length=4096)]


class ApplicationIdentity(ProtocolModel):
    """A namespaced recognition key and a human-readable application name."""

    ident: ApplicationId
    name: Annotated[str, Field(min_length=1, max_length=512)]
