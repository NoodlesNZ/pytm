"""AWS service components for pytm.

Provides first-class threat model elements for common AWS services,
enabling AWS-specific threat rules.

Service elements (extend pytm.Element / Asset / Datastore)::

    from pytm.aws import EC2Instance, S3Bucket, RDSInstance
    from pytm.aws import LambdaFunction, SQSQueue, APIGateway, IAMRole

    web = EC2Instance("web-server", publiclyAccessible=True, imdsv2Required=False)
    store = S3Bucket("user-data", publicRead=True, encrypted=False)

Network boundary elements (extend pytm.Boundary)::

    from pytm.aws import AWSRegion, AWSVPC, AWSSubnet

    region   = AWSRegion("US East", regionCode="us-east-1")
    vpc      = AWSVPC("Production VPC", cidr="10.0.0.0/16", inBoundary=region)
    pub_sub  = AWSSubnet("Public A", cidr="10.0.0.0/24", isPublic=True, inBoundary=vpc)
    priv_sub = AWSSubnet("App A",    cidr="10.0.1.0/24", isPublic=False, inBoundary=vpc)

    server = EC2Instance("web", inBoundary=priv_sub)
"""

# ── Network boundaries ───────────────────────────────────────────────────────
from .region import AWSRegion
from .vpc import AWSVPC
from .subnet import AWSSubnet

# ── Service elements ─────────────────────────────────────────────────────────
from .alb import ALB
from .apigateway import APIGateway
from .cloudfront import CloudFrontDistribution
from .ec2 import EC2Instance
from .efs import EFSFileSystem
from .elasticache import ElastiCacheCluster
from .iam import IAMRole
from .lambda_function import LambdaFunction
from .rds import RDSInstance
from .s3 import S3Bucket
from .sqs import SQSQueue

__all__ = [
    # Network boundaries
    "AWSRegion",
    "AWSVPC",
    "AWSSubnet",
    # Service elements
    "ALB",
    "APIGateway",
    "CloudFrontDistribution",
    "EC2Instance",
    "EFSFileSystem",
    "ElastiCacheCluster",
    "IAMRole",
    "LambdaFunction",
    "RDSInstance",
    "S3Bucket",
    "SQSQueue",
]
