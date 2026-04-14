"""Application Load Balancer element for AWS threat modeling."""

from pydantic import Field

from pytm.asset import Asset


class ALB(Asset):
    """An AWS Application Load Balancer.

    Attributes:
        isInternal (bool): Is the ALB internal (not internet-facing)?
        loggingEnabled (bool): Is ALB access logging to S3 enabled?
        deletionProtection (bool): Is deletion protection enabled?
        httpsOnly (bool): Are HTTP listeners redirected to HTTPS?
        hasWAF (bool): Is an AWS WAF web ACL attached?
        desyncMitigationMode (str): HTTP desync mitigation mode ("monitor", "defensive", "strictest")
        dropInvalidHeaders (bool): Are invalid HTTP headers dropped?
    """

    isInternal: bool = Field(
        default=False, description="Is the ALB internal (not internet-facing)?"
    )
    loggingEnabled: bool = Field(
        default=False, description="Is ALB access logging to S3 enabled?"
    )
    deletionProtection: bool = Field(
        default=False, description="Is deletion protection enabled?"
    )
    httpsOnly: bool = Field(
        default=False, description="Are HTTP listeners redirected to HTTPS?"
    )
    hasWAF: bool = Field(default=False, description="Is an AWS WAF web ACL attached?")
    desyncMitigationMode: str = Field(
        default="defensive",
        description="HTTP desync mitigation mode ('monitor', 'defensive', 'strictest')",
    )
    dropInvalidHeaders: bool = Field(
        default=False, description="Are invalid HTTP headers dropped?"
    )

    def _shape(self) -> str:
        return "invtriangle"
