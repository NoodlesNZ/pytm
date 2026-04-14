"""SQS queue element for AWS threat modeling."""

from pydantic import Field

from pytm.asset import Asset


class SQSQueue(Asset):
    """An AWS SQS queue.

    Attributes:
        encrypted (bool): Is server-side encryption enabled (SSE-SQS or SSE-KMS)?
        isFIFO (bool): Is this a FIFO queue?
        isDeadLetterQueue (bool): Is this queue used as a dead-letter queue?
        visibilityTimeout (int): Visibility timeout in seconds
        publiclyAccessible (bool): Does the queue policy allow public access?
        crossAccountAccess (bool): Does the queue policy grant cross-account access?
        dlqConfigured (bool): Is a dead-letter queue configured for this queue?
    """

    encrypted: bool = Field(default=False, description="Is server-side encryption enabled?")
    isFIFO: bool = Field(default=False, description="Is this a FIFO queue?")
    isDeadLetterQueue: bool = Field(
        default=False, description="Is this queue used as a dead-letter queue?"
    )
    visibilityTimeout: int = Field(
        default=30, description="Visibility timeout in seconds"
    )
    publiclyAccessible: bool = Field(
        default=False, description="Does the queue policy allow public access?"
    )
    crossAccountAccess: bool = Field(
        default=False, description="Does the queue policy grant cross-account access?"
    )
    dlqConfigured: bool = Field(
        default=False, description="Is a dead-letter queue configured for this queue?"
    )

    def _shape(self) -> str:
        return "parallelogram"
