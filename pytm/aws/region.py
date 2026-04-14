"""AWS Region boundary for threat modeling."""

from typing import List

from pydantic import Field

from pytm.boundary import Boundary


# Valid AWS region codes for validation / documentation purposes.
KNOWN_REGIONS = {
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ca-central-1",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "eu-north-1", "eu-south-1",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-southeast-1", "ap-southeast-2",
    "ap-south-1", "ap-east-1",
    "sa-east-1",
    "me-south-1",
    "af-south-1",
}


class AWSRegion(Boundary):
    """An AWS region boundary.

    Represents a geographic AWS region (e.g. us-east-1). All VPCs, managed
    services, and global edge resources associated with the region should have
    ``inBoundary`` set to this object.

    Attributes:
        regionCode (str): AWS region identifier (e.g. "us-east-1")
        isGovCloud (bool): Is this an AWS GovCloud (US) region?
        dataResidencyRequired (bool): Does regulatory policy require data to remain in this region?
    """

    regionCode: str = Field(
        default="",
        description="AWS region identifier (e.g. 'us-east-1')",
    )
    isGovCloud: bool = Field(
        default=False,
        description="Is this an AWS GovCloud (US) region?",
    )
    dataResidencyRequired: bool = Field(
        default=False,
        description="Does regulatory policy require data to remain in this region?",
    )

    def _label(self) -> str:
        parts = [self.name]
        if self.regionCode:
            parts.append(self.regionCode)
        return "\\n".join(parts)

    def _color(self, **kwargs) -> str:
        return "royalblue3"
