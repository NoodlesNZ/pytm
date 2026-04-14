"""IAM Role element for AWS threat modeling."""

from typing import List

from pydantic import Field

from pytm.element import Element


class IAMRole(Element):
    """An AWS IAM role.

    IAMRole models the identity and access configuration for an AWS principal.
    It does not participate in dataflows directly but can be associated with
    other elements (e.g. an EC2Instance or LambdaFunction) to model permission chains.

    Attributes:
        isServiceRole (bool): Is this a service-linked or service role?
        hasBoundary (bool): Is a permissions boundary policy attached?
        hasInlinePolicy (bool): Does the role have inline (embedded) policies?
        managedPolicies (List[str]): Names of attached AWS-managed or customer-managed policies
        crossAccountTrust (bool): Does the trust policy allow cross-account assumption?
        hasAdminAccess (bool): Does the role have administrator-level permissions?
        requiresMFA (bool): Does the trust policy require MFA to assume the role?
        hasConditions (bool): Does the trust policy include condition keys?
    """

    isServiceRole: bool = Field(
        default=False, description="Is this a service-linked or service role?"
    )
    hasBoundary: bool = Field(
        default=False, description="Is a permissions boundary policy attached?"
    )
    hasInlinePolicy: bool = Field(
        default=False, description="Does the role have inline (embedded) policies?"
    )
    managedPolicies: List[str] = Field(
        default_factory=list,
        description="Names of attached AWS-managed or customer-managed policies",
    )
    crossAccountTrust: bool = Field(
        default=False,
        description="Does the trust policy allow cross-account assumption?",
    )
    hasAdminAccess: bool = Field(
        default=False,
        description="Does the role have administrator-level permissions?",
    )
    requiresMFA: bool = Field(
        default=False,
        description="Does the trust policy require MFA to assume the role?",
    )
    hasConditions: bool = Field(
        default=False,
        description="Does the trust policy include condition keys?",
    )
