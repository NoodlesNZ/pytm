"""API Gateway element for AWS threat modeling."""

from pydantic import Field

from pytm.asset import Asset


class APIGateway(Asset):
    """An AWS API Gateway (REST, HTTP, or WebSocket).

    Attributes:
        apiType (str): Gateway type — "REST", "HTTP", or "WebSocket"
        hasWAF (bool): Is an AWS WAF web ACL attached?
        loggingEnabled (bool): Is access logging to CloudWatch enabled?
        tracingEnabled (bool): Is AWS X-Ray tracing enabled?
        requiresAPIKey (bool): Do API methods require an API key?
        hasAuthorizer (bool): Is a Lambda or Cognito authorizer configured?
        isPrivate (bool): Is the API private (accessible only within a VPC)?
        tlsMinVersion (str): Minimum TLS version enforced (e.g. "TLS_1_2")
        throttlingEnabled (bool): Are default throttle limits configured?
    """

    apiType: str = Field(
        default="REST", description="Gateway type — 'REST', 'HTTP', or 'WebSocket'"
    )
    hasWAF: bool = Field(default=False, description="Is an AWS WAF web ACL attached?")
    loggingEnabled: bool = Field(
        default=False, description="Is access logging to CloudWatch enabled?"
    )
    tracingEnabled: bool = Field(
        default=False, description="Is AWS X-Ray tracing enabled?"
    )
    requiresAPIKey: bool = Field(
        default=False, description="Do API methods require an API key?"
    )
    hasAuthorizer: bool = Field(
        default=False, description="Is a Lambda or Cognito authorizer configured?"
    )
    isPrivate: bool = Field(
        default=False, description="Is the API private (accessible only within a VPC)?"
    )
    tlsMinVersion: str = Field(
        default="TLS_1_2", description="Minimum TLS version enforced"
    )
    throttlingEnabled: bool = Field(
        default=False, description="Are default throttle limits configured?"
    )

    def _shape(self) -> str:
        return "trapezium"
