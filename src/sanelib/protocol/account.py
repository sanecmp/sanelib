"""Local operating-system account wire models."""

from typing import Annotated

from pydantic import Field

from ..utils.validation import NonNegativeInt
from .base import ProtocolModel


class DiscoveredAccount(ProtocolModel):
    """One local account reported by sanex."""

    uid: NonNegativeInt
    login: Annotated[str, Field(min_length=1, max_length=256, strict=True)]
    name: Annotated[str, Field(min_length=1, max_length=256, strict=True)]
