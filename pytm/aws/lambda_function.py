"""Lambda function element for AWS threat modeling."""

from pydantic import Field

from pytm.asset import Lambda


class LambdaFunction(Lambda):
    """An AWS Lambda function.

    Extends the base Lambda class with AWS-specific security properties.

    Attributes:
        vpcEnabled (bool): Is the function deployed inside a VPC?
        hasResourceBasedPolicy (bool): Does the function have a resource-based policy?
        reservedConcurrency (int): Reserved concurrency limit (-1 means unrestricted)
        xrayTracingEnabled (bool): Is AWS X-Ray tracing enabled?
        codeSigningEnabled (bool): Is code signing enforced?
        hasSecretsManagerIntegration (bool): Does the function fetch secrets from Secrets Manager?
        hasLayerWithSensitiveData (bool): Does a Lambda layer expose sensitive data?
        dlqConfigured (bool): Is a dead-letter queue configured?
    """

    vpcEnabled: bool = Field(
        default=False, description="Is the function deployed inside a VPC?"
    )
    hasResourceBasedPolicy: bool = Field(
        default=False, description="Does the function have a resource-based policy?"
    )
    reservedConcurrency: int = Field(
        default=-1, description="Reserved concurrency limit (-1 means unrestricted)"
    )
    xrayTracingEnabled: bool = Field(
        default=False, description="Is AWS X-Ray tracing enabled?"
    )
    codeSigningEnabled: bool = Field(
        default=False, description="Is code signing enforced?"
    )
    hasSecretsManagerIntegration: bool = Field(
        default=False,
        description="Does the function fetch secrets from Secrets Manager?",
    )
    hasLayerWithSensitiveData: bool = Field(
        default=False, description="Does a Lambda layer expose sensitive data?"
    )
    dlqConfigured: bool = Field(
        default=False, description="Is a dead-letter queue configured?"
    )
