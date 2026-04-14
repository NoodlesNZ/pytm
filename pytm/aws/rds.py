"""RDS instance element for AWS threat modeling."""

from pydantic import Field

from pytm.datastore import Datastore


class RDSInstance(Datastore):
    """An AWS RDS database instance.

    Attributes:
        engine (str): Database engine (e.g. "mysql", "postgres", "aurora")
        engineVersion (str): Engine version string
        publiclyAccessible (bool): Is the instance reachable from the internet?
        encrypted (bool): Is storage encryption enabled?
        multiAZ (bool): Is Multi-AZ failover enabled?
        backupEnabled (bool): Are automated backups enabled?
        iamAuthentication (bool): Is IAM database authentication enabled?
        deletionProtection (bool): Is deletion protection on?
        performanceInsightsEnabled (bool): Is Performance Insights enabled?
        enhancedMonitoring (bool): Is enhanced monitoring enabled?
        autoMinorVersionUpgrade (bool): Are minor version upgrades applied automatically?
    """

    engine: str = Field(
        default="", description="Database engine (e.g. 'mysql', 'postgres', 'aurora')"
    )
    engineVersion: str = Field(default="", description="Engine version string")
    publiclyAccessible: bool = Field(
        default=False, description="Is the instance reachable from the internet?"
    )
    encrypted: bool = Field(default=False, description="Is storage encryption enabled?")
    multiAZ: bool = Field(default=False, description="Is Multi-AZ failover enabled?")
    backupEnabled: bool = Field(default=False, description="Are automated backups enabled?")
    iamAuthentication: bool = Field(
        default=False, description="Is IAM database authentication enabled?"
    )
    deletionProtection: bool = Field(
        default=False, description="Is deletion protection on?"
    )
    performanceInsightsEnabled: bool = Field(
        default=False, description="Is Performance Insights enabled?"
    )
    enhancedMonitoring: bool = Field(
        default=False, description="Is enhanced monitoring enabled?"
    )
    autoMinorVersionUpgrade: bool = Field(
        default=True, description="Are minor version upgrades applied automatically?"
    )
