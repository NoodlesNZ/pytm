"""EC2 instance element for AWS threat modeling."""

from pydantic import Field

from pytm.asset import Asset


class EC2Instance(Asset):
    """An AWS EC2 instance.

    Attributes:
        instanceType (str): EC2 instance type (e.g. "t3.micro")
        publiclyAccessible (bool): Is the instance reachable from the internet?
        hasPublicIP (bool): Does the instance have a public IP address?
        iamRoleAttached (bool): Is an IAM instance profile attached?
        encryptedStorage (bool): Are EBS volumes encrypted?
        multiAZ (bool): Is the instance spread across availability zones?
        securityGroupsOpen (bool): Do security groups allow broad inbound access?
        imdsv2Required (bool): Is IMDSv2 (hop-limit token) enforced?
        ssmEnabled (bool): Is the instance managed via SSM Session Manager?
    """

    instanceType: str = Field(default="", description="EC2 instance type (e.g. 't3.micro')")
    publiclyAccessible: bool = Field(
        default=False, description="Is the instance reachable from the internet?"
    )
    hasPublicIP: bool = Field(
        default=False, description="Does the instance have a public IP address?"
    )
    iamRoleAttached: bool = Field(
        default=False, description="Is an IAM instance profile attached?"
    )
    encryptedStorage: bool = Field(
        default=False, description="Are EBS volumes encrypted?"
    )
    multiAZ: bool = Field(
        default=False, description="Is the instance spread across availability zones?"
    )
    securityGroupsOpen: bool = Field(
        default=False, description="Do security groups allow broad inbound access?"
    )
    imdsv2Required: bool = Field(
        default=False, description="Is IMDSv2 (hop-limit token) enforced?"
    )
    ssmEnabled: bool = Field(
        default=False, description="Is the instance managed via SSM Session Manager?"
    )

    def _shape(self) -> str:
        return "box"
