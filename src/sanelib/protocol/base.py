"""Base model for immutable strict wire messages."""

from pydantic import BaseModel, ConfigDict


class ProtocolModel(BaseModel):
    """Reject implicit conversions and unknown wire fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
