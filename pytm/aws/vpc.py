"""AWS VPC boundary for threat modeling."""

from pydantic import Field

from pytm.boundary import Boundary


class AWSVPC(Boundary):
    """An AWS Virtual Private Cloud (VPC) boundary.

    A VPC is a logically isolated network within an AWS region. Set
    ``inBoundary`` to an :class:`AWSRegion` to express containment.

    Attributes:
        cidr (str): Primary IPv4 CIDR block (e.g. "10.0.0.0/16")
        enableDnsSupport (bool): Is DNS resolution via AmazonProvidedDNS enabled?
        enableDnsHostnames (bool): Are public DNS hostnames assigned to instances with public IPs?
        flowLogsEnabled (bool): Are VPC Flow Logs enabled?
        isDefault (bool): Is this the AWS-managed default VPC?
        hasInternetGateway (bool): Is an Internet Gateway attached?
        hasNatGateway (bool): Are NAT Gateways deployed for private subnet egress?
        peeringEnabled (bool): Does the VPC have active VPC peering connections?
        privateLink (bool): Are VPC endpoints (PrivateLink) used for AWS service access?
    """

    cidr: str = Field(
        default="",
        description="Primary IPv4 CIDR block (e.g. '10.0.0.0/16')",
    )
    enableDnsSupport: bool = Field(
        default=True,
        description="Is DNS resolution via AmazonProvidedDNS enabled?",
    )
    enableDnsHostnames: bool = Field(
        default=False,
        description="Are public DNS hostnames assigned to instances with public IPs?",
    )
    flowLogsEnabled: bool = Field(
        default=False,
        description="Are VPC Flow Logs enabled?",
    )
    isDefault: bool = Field(
        default=False,
        description="Is this the AWS-managed default VPC?",
    )
    hasInternetGateway: bool = Field(
        default=False,
        description="Is an Internet Gateway attached?",
    )
    hasNatGateway: bool = Field(
        default=False,
        description="Are NAT Gateways deployed for private subnet egress?",
    )
    peeringEnabled: bool = Field(
        default=False,
        description="Does the VPC have active VPC peering connections?",
    )
    privateLink: bool = Field(
        default=False,
        description="Are VPC endpoints (PrivateLink) used for AWS service access?",
    )

    def _label(self) -> str:
        parts = [self.name]
        if self.cidr:
            parts.append(self.cidr)
        return "\\n".join(parts)

    def _color(self, **kwargs) -> str:
        return "darkorange2"
