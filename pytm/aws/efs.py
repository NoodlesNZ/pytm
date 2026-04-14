"""EFS file system element for AWS threat modeling."""

from pydantic import Field

from pytm.datastore import Datastore


class EFSFileSystem(Datastore):
    """An AWS Elastic File System (EFS) file system.

    Attributes:
        encrypted (bool): Is encryption at rest enabled?
        performanceMode (str): Performance mode — "generalPurpose" or "maxIO"
        throughputMode (str): Throughput mode — "bursting" or "provisioned"
        inTransitEncryption (bool): Is TLS enforced for NFS mount connections?
        backupEnabled (bool): Is AWS Backup integration enabled?
        lifecyclePolicyDays (int): Days before infrequently accessed files are tiered (0 = disabled)
        publiclyAccessible (bool): Is the file system reachable outside the VPC?
    """

    encrypted: bool = Field(default=False, description="Is encryption at rest enabled?")
    performanceMode: str = Field(
        default="generalPurpose",
        description="Performance mode — 'generalPurpose' or 'maxIO'",
    )
    throughputMode: str = Field(
        default="bursting",
        description="Throughput mode — 'bursting' or 'provisioned'",
    )
    inTransitEncryption: bool = Field(
        default=False,
        description="Is TLS enforced for NFS mount connections?",
    )
    backupEnabled: bool = Field(
        default=False, description="Is AWS Backup integration enabled?"
    )
    lifecyclePolicyDays: int = Field(
        default=0,
        description="Days before infrequently accessed files are tiered (0 = disabled)",
    )
    publiclyAccessible: bool = Field(
        default=False,
        description="Is the file system reachable outside the VPC?",
    )
