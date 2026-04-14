"""AWS Subnet boundary for threat modeling."""

from pydantic import Field

from pytm.boundary import Boundary


class AWSSubnet(Boundary):
    """An AWS subnet boundary.

    A subnet is a range of IP addresses within a VPC, scoped to a single
    Availability Zone. Set ``inBoundary`` to an :class:`AWSVPC` to express
    containment. Elements (EC2 instances, RDS instances, etc.) that reside in
    the subnet should have ``inBoundary`` set to this object.

    Attributes:
        cidr (str): IPv4 CIDR block for the subnet (e.g. "10.0.0.0/24")
        availabilityZone (str): Availability Zone identifier (e.g. "us-east-1a")
        isPublic (bool): Does the subnet have a route to an Internet Gateway?
        mapPublicIpOnLaunch (bool): Are public IP addresses assigned to instances at launch?
        hasNaclIngress (bool): Is a custom inbound Network ACL applied (not the default allow-all)?
        hasNaclEgress (bool): Is a custom outbound Network ACL applied?
    """

    cidr: str = Field(
        default="",
        description="IPv4 CIDR block for the subnet (e.g. '10.0.0.0/24')",
    )
    availabilityZone: str = Field(
        default="",
        description="Availability Zone identifier (e.g. 'us-east-1a')",
    )
    isPublic: bool = Field(
        default=False,
        description="Does the subnet have a route to an Internet Gateway?",
    )
    mapPublicIpOnLaunch: bool = Field(
        default=False,
        description="Are public IP addresses assigned to instances at launch?",
    )
    hasNaclIngress: bool = Field(
        default=False,
        description="Is a custom inbound Network ACL applied (not the default allow-all)?",
    )
    hasNaclEgress: bool = Field(
        default=False,
        description="Is a custom outbound Network ACL applied?",
    )

    def _label(self) -> str:
        parts = [self.name]
        if self.cidr:
            parts.append(self.cidr)
        if self.availabilityZone:
            parts.append(self.availabilityZone)
        tier = "public" if self.isPublic else "private"
        parts.append(f"[{tier}]")
        return "\\n".join(parts)

    def _color(self, **kwargs) -> str:
        # Public subnets rendered differently to private — makes DFDs easier to read.
        return "orangered" if self.isPublic else "seagreen4"
