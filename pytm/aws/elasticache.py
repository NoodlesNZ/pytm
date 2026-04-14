"""ElastiCache cluster element for AWS threat modeling."""

from pydantic import Field

from pytm.datastore import Datastore


class ElastiCacheCluster(Datastore):
    """An AWS ElastiCache cluster (Redis or Memcached).

    Attributes:
        engine (str): Cache engine — "redis" or "memcached"
        engineVersion (str): Engine version string
        encrypted (bool): Is in-transit and at-rest encryption enabled?
        authEnabled (bool): Is AUTH token (Redis) or SASL (Memcached) authentication enabled?
        multiAZ (bool): Is Multi-AZ automatic failover enabled (Redis)?
        publiclyAccessible (bool): Is the cluster endpoint reachable from outside the VPC?
        autoMinorVersionUpgrade (bool): Are minor engine version upgrades applied automatically?
        snapshotEnabled (bool): Are automatic snapshots enabled (Redis)?
    """

    engine: str = Field(
        default="redis", description="Cache engine — 'redis' or 'memcached'"
    )
    engineVersion: str = Field(default="", description="Engine version string")
    encrypted: bool = Field(
        default=False,
        description="Is in-transit and at-rest encryption enabled?",
    )
    authEnabled: bool = Field(
        default=False,
        description="Is AUTH token (Redis) or SASL (Memcached) authentication enabled?",
    )
    multiAZ: bool = Field(
        default=False,
        description="Is Multi-AZ automatic failover enabled (Redis)?",
    )
    publiclyAccessible: bool = Field(
        default=False,
        description="Is the cluster endpoint reachable from outside the VPC?",
    )
    autoMinorVersionUpgrade: bool = Field(
        default=True,
        description="Are minor engine version upgrades applied automatically?",
    )
    snapshotEnabled: bool = Field(
        default=False, description="Are automatic snapshots enabled (Redis)?"
    )
