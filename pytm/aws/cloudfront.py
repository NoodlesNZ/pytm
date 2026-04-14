"""CloudFront distribution element for AWS threat modeling."""

from pydantic import Field

from pytm.asset import Asset


class CloudFrontDistribution(Asset):
    """An AWS CloudFront distribution (CDN layer).

    Attributes:
        hasWAF (bool): Is an AWS WAF web ACL attached to the distribution?
        loggingEnabled (bool): Is CloudFront access logging enabled?
        httpsOnly (bool): Is the viewer protocol policy set to HTTPS-only or redirect?
        tlsMinVersion (str): Minimum TLS version for viewer connections (e.g. "TLSv1.2_2021")
        geoRestrictionEnabled (bool): Is geographic restriction configured?
        originAccessControl (bool): Is Origin Access Control used to restrict S3 origin access?
        fieldLevelEncryption (bool): Is field-level encryption enabled for sensitive fields?
        customErrorPages (bool): Are custom error pages configured (avoids leaking origin error details)?
    """

    hasWAF: bool = Field(
        default=False, description="Is an AWS WAF web ACL attached to the distribution?"
    )
    loggingEnabled: bool = Field(
        default=False, description="Is CloudFront access logging enabled?"
    )
    httpsOnly: bool = Field(
        default=False,
        description="Is the viewer protocol policy set to HTTPS-only or redirect?",
    )
    tlsMinVersion: str = Field(
        default="TLSv1",
        description="Minimum TLS version for viewer connections",
    )
    geoRestrictionEnabled: bool = Field(
        default=False, description="Is geographic restriction configured?"
    )
    originAccessControl: bool = Field(
        default=False,
        description="Is Origin Access Control used to restrict S3 origin access?",
    )
    fieldLevelEncryption: bool = Field(
        default=False,
        description="Is field-level encryption enabled for sensitive fields?",
    )
    customErrorPages: bool = Field(
        default=False,
        description="Are custom error pages configured?",
    )

    def _shape(self) -> str:
        return "diamond"
