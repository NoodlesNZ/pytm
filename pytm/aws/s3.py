"""S3 bucket element for AWS threat modeling."""

from pydantic import Field

from pytm.datastore import Datastore


class S3Bucket(Datastore):
    """An AWS S3 bucket.

    Attributes:
        publicRead (bool): Is the bucket publicly readable?
        publicWrite (bool): Is the bucket publicly writable?
        versioned (bool): Is S3 versioning enabled?
        encrypted (bool): Is server-side encryption enabled?
        loggingEnabled (bool): Is S3 server access logging enabled?
        mfaDeleteEnabled (bool): Is MFA delete required?
        blockPublicAccess (bool): Is the S3 Block Public Access setting on?
        crossAccountAccess (bool): Does the bucket policy grant cross-account access?
        replicationEnabled (bool): Is cross-region replication configured?
    """

    publicRead: bool = Field(default=False, description="Is the bucket publicly readable?")
    publicWrite: bool = Field(default=False, description="Is the bucket publicly writable?")
    versioned: bool = Field(default=False, description="Is S3 versioning enabled?")
    encrypted: bool = Field(default=False, description="Is server-side encryption enabled?")
    loggingEnabled: bool = Field(
        default=False, description="Is S3 server access logging enabled?"
    )
    mfaDeleteEnabled: bool = Field(
        default=False, description="Is MFA delete required?"
    )
    blockPublicAccess: bool = Field(
        default=False, description="Is the S3 Block Public Access setting on?"
    )
    crossAccountAccess: bool = Field(
        default=False, description="Does the bucket policy grant cross-account access?"
    )
    replicationEnabled: bool = Field(
        default=False, description="Is cross-region replication configured?"
    )
