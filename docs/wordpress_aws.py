"""AWS Reference Architecture for WordPress — threat model.

Source architecture: https://github.com/aws-samples/aws-refarch-wordpress

Architecture overview
---------------------

                    ┌─────────────────────────────────────────────┐
  Internet          │  Internet                                    │
  ─────────         │  ┌────────────┐    ┌─────────────────────┐  │
  End Users ───────►│  │ CloudFront │    │ Route 53 (optional) │  │
  Admins            │  └─────┬──────┘    └─────────────────────┘  │
                    │        │                                     │
                    └────────┼────────────────────────────────────-┘
                             │
                    ┌────────▼───────────────────────────────────────────────┐
                    │  VPC (10.0.0.0/16)                                     │
                    │                                                         │
                    │  ┌─ Public Subnets ──────────────────────────────────┐ │
                    │  │  NAT GW (AZ-a)   NAT GW (AZ-b)                   │ │
                    │  │  ┌──────────────────────────────────────────────┐ │ │
                    │  │  │ Application Load Balancer (internet-facing)  │ │ │
                    │  │  └──────────────────────────────────────────────┘ │ │
                    │  └───────────────────────────────────────────────────┘ │
                    │           │                                             │
                    │  ┌─ Web/App Subnets ─────────────────────────────────┐ │
                    │  │  ┌──────────────────────┐  ┌───────────────────┐  │ │
                    │  │  │  EC2 ASG             │  │  Bastion Host     │  │ │
                    │  │  │  (WordPress + Apache │  │  (desired: 0)     │  │ │
                    │  │  │  + PHP + OPcache)    │  └───────────────────┘  │ │
                    │  │  │  Min: 2  Max: 30     │                          │ │
                    │  │  └──────────────────────┘                          │ │
                    │  └───────────────────────────────────────────────────┘ │
                    │           │            │           │                    │
                    │  ┌─ Data Subnets ─────────────────────────────────────┐ │
                    │  │  ┌───────────┐  ┌──────────┐  ┌────────────────┐  │ │
                    │  │  │ Aurora    │  │  EFS     │  │  ElastiCache   │  │ │
                    │  │  │ MySQL     │  │ (shared  │  │  Memcached     │  │ │
                    │  │  │ Multi-AZ  │  │  /var/   │  │  (query cache) │  │ │
                    │  │  │           │  │   www)   │  │                │  │ │
                    │  │  └───────────┘  └──────────┘  └────────────────┘  │ │
                    │  └───────────────────────────────────────────────────┘ │
                    └────────────────────────────────────────────────────────┘

  Optional static-asset offload:
    WordPress (W3 Total Cache plugin) → S3 → CloudFront

Run:
    poetry run python docs/wordpress_aws.py --report
"""

import json
import os
import sys

import pytm
from pytm import TM, Actor, Boundary, Dataflow, Threat
from pytm.aws import (
    ALB,
    AWSRegion,
    AWSSubnet,
    AWSVPC,
    CloudFrontDistribution,
    EC2Instance,
    EFSFileSystem,
    ElastiCacheCluster,
    IAMRole,
    LambdaFunction,
    RDSInstance,
    S3Bucket,
)

# ---------------------------------------------------------------------------
# Threat libraries
# ---------------------------------------------------------------------------

def _load_threats(*filenames: str) -> list:
    threats = []
    base = os.path.join(os.path.dirname(pytm.__file__), "threatlib")
    for name in filenames:
        path = os.path.join(base, name)
        if os.path.exists(path):
            with open(path) as f:
                threats.extend(Threat(**t) for t in json.load(f))
    return threats

# ---------------------------------------------------------------------------
# Threat model
# ---------------------------------------------------------------------------

tm = TM(
    "WordPress on AWS (aws-refarch-wordpress)",
    description=(
        "Production WordPress deployment following the AWS reference architecture. "
        "Multi-AZ VPC with CloudFront CDN, internet-facing ALB, Auto Scaling EC2 "
        "app tier, Aurora MySQL Multi-AZ, shared EFS filesystem, and ElastiCache "
        "Memcached for query caching. Static assets offloaded to S3 + CloudFront."
    ),
)
tm.threats = _load_threats("threats.json", "threats_aws.json")

# ── Boundaries ──────────────────────────────────────────────────────────────
# Uses the AWS-specific boundary hierarchy so threat rules targeting
# AWSRegion, AWSVPC, and AWSSubnet fire correctly.
#
# Containment:
#   Internet (plain Boundary — outside AWS)
#   AWSRegion "us-east-1"
#     └── AWSVPC "Production VPC" (10.0.0.0/16)
#           ├── AWSSubnet "Public Subnets"  (isPublic=True)   — ALB, NAT GWs
#           ├── AWSSubnet "Web/App Subnets" (isPublic=False)  — EC2 ASG, Bastion
#           └── AWSSubnet "Data Subnets"    (isPublic=False)  — Aurora, EFS, ElastiCache

internet = Boundary("Internet")

region = AWSRegion(
    "us-east-1",
    regionCode="us-east-1",
    dataResidencyRequired=False,
)

vpc = AWSVPC(
    "Production VPC",
    inBoundary=region,
    cidr="10.0.0.0/16",
    enableDnsSupport=True,
    enableDnsHostnames=True,
    flowLogsEnabled=False,      # not enabled in the reference architecture — flagged
    isDefault=False,
    hasInternetGateway=True,
    hasNatGateway=True,         # one NAT GW per AZ in the reference arch
    peeringEnabled=False,
    privateLink=False,
)

public_subnet = AWSSubnet(
    "Public Subnets",
    inBoundary=vpc,
    cidr="10.0.200.0/22",       # 10.0.200–203.x across AZs (reference arch default)
    isPublic=True,
    mapPublicIpOnLaunch=False,  # ALB and NAT GWs use EIPs; EC2 not launched here
    hasNaclIngress=False,       # default NACL in reference arch
    hasNaclEgress=False,
)

web_subnet = AWSSubnet(
    "Web/App Subnets",
    inBoundary=vpc,
    cidr="10.0.0.0/20",         # 10.0.0–15.x across AZs
    isPublic=False,
    mapPublicIpOnLaunch=False,
    hasNaclIngress=False,       # default NACL — flagged
    hasNaclEgress=False,
)

data_subnet = AWSSubnet(
    "Data Subnets",
    inBoundary=vpc,
    cidr="10.0.100.0/22",       # 10.0.100–103.x across AZs
    isPublic=False,
    mapPublicIpOnLaunch=False,
    hasNaclIngress=False,       # default NACL — flagged
    hasNaclEgress=False,
)

# ── External actors ─────────────────────────────────────────────────────────

end_user = Actor("End User",    inBoundary=internet)
admin    = Actor("Admin",       inBoundary=internet)   # reaches Bastion via SSH

# ── Edge layer ──────────────────────────────────────────────────────────────
# CloudFront sits in front of the ALB and also serves the static-asset bucket.
# The reference architecture makes CloudFront optional; modelled here as
# deployed (the recommended production configuration).

cdn = CloudFrontDistribution(
    "WordPress CDN",
    inBoundary=internet,            # CloudFront is a global edge service
    httpsOnly=True,                 # HTTP → HTTPS redirect for viewer connections
    tlsMinVersion="TLSv1.2_2021",
    hasWAF=True,                    # WAF Web ACL protecting the distribution
    loggingEnabled=True,
    originAccessControl=True,       # protects the S3 static-assets origin
    customErrorPages=True,
    # Cache behaviours per reference arch:
    #   /wp-includes/* and /wp-content/* → 900 s TTL
    #   /* → 0 s TTL (dynamic; pass-through to ALB origin)
)

# ── Presentation tier — public subnets ──────────────────────────────────────
# Internet-facing ALB. HTTPS listener with ACM certificate; HTTP listener
# redirects to HTTPS. Health check target: /wp-login.php.

alb = ALB(
    "WordPress ALB",
    inBoundary=public_subnet,
    isInternal=False,               # internet-facing
    httpsOnly=True,                 # HTTP listener → 301 redirect to HTTPS
    loggingEnabled=True,            # access logs to S3
    deletionProtection=True,
    dropInvalidHeaders=True,
    hasWAF=False,                   # WAF is at CloudFront; ALB restricted to CF prefix list
)

# ── Application tier — web/app subnets ──────────────────────────────────────
# EC2 Auto Scaling Group running Amazon Linux 2 + Apache + PHP + WordPress.
# Each instance mounts the shared EFS volume at /var/www/wordpress.

web_role = IAMRole(
    "WordPress EC2 Role",
    inBoundary=web_subnet,
    isServiceRole=True,
    hasBoundary=False,              # reference arch does not define a permissions boundary
    hasAdminAccess=False,
    hasInlinePolicy=False,
    crossAccountTrust=False,
    # Actual permissions: CloudWatch Logs (CreateLogGroup, CreateLogStream,
    # PutLogEvents, DescribeLogStreams) only — least privilege per the CFN template.
    managedPolicies=["CloudWatchLogsFullAccess"],
)

wordpress_asg = EC2Instance(
    "WordPress EC2 (ASG)",
    inBoundary=web_subnet,
    instanceType="t3.medium",      # user-configurable; t3 / m5 / c5 families
    publiclyAccessible=False,      # no public IPs — private subnet, reached via ALB
    hasPublicIP=False,
    iamRoleAttached=True,          # web_role above
    encryptedStorage=False,        # root EBS not encrypted in base template (configurable)
    imdsv2Required=False,          # reference arch uses IMDSv1 (launch config, not template)
    ssmEnabled=False,              # SSH via Bastion is the admin path in the reference arch
    securityGroupsOpen=False,      # WebSecurityGroup: only ALB SG and Bastion SG as sources
    # OS: Amazon Linux 2, Apache 2.4, PHP (version selectable), OPcache
    # Software: WordPress + W3 Total Cache plugin
    OS="Amazon Linux 2",
)

# Bastion host — Auto Scaling Group with desired: 0 (zero cost at rest).
# Launched on demand; SSH source CIDR is user-configurable (defaults to 0.0.0.0/0
# in the reference arch — flagged as a finding below).

bastion_role = IAMRole(
    "Bastion EC2 Role",
    inBoundary=web_subnet,
    isServiceRole=True,
    hasAdminAccess=False,
    hasInlinePolicy=False,
    managedPolicies=["CloudWatchLogsFullAccess"],
)

bastion = EC2Instance(
    "Bastion Host",
    inBoundary=web_subnet,
    instanceType="t3.nano",
    publiclyAccessible=True,        # must be reachable for SSH ingress
    hasPublicIP=True,
    iamRoleAttached=True,
    encryptedStorage=False,
    imdsv2Required=False,
    ssmEnabled=False,
    securityGroupsOpen=True,        # default SSH source is 0.0.0.0/0 — intentional finding
)

# ── Data tier — data subnets ─────────────────────────────────────────────────

# Aurora MySQL cluster — Multi-AZ with automatic failover.
# Two instances across separate AZs; cluster endpoint used by WordPress.
db = RDSInstance(
    "Aurora MySQL Cluster",
    inBoundary=data_subnet,
    engine="aurora-mysql",
    engineVersion="8.0",
    publiclyAccessible=False,       # private subnet, no public endpoint
    encrypted=False,                # optional in reference arch; flagged as finding
    multiAZ=True,                   # two instances across AZs
    backupEnabled=True,             # 30-day retention
    iamAuthentication=False,        # not enabled in reference arch; WordPress uses password
    deletionProtection=False,       # not set in reference arch CFN template
    performanceInsightsEnabled=False,
    autoMinorVersionUpgrade=True,
)

# EFS — shared NFS filesystem mounted at /var/www/wordpress on every EC2 instance.
# Mount targets in each data subnet (one per AZ) so all ASG instances share
# the same WordPress installation files and uploaded media.
efs = EFSFileSystem(
    "WordPress EFS",
    inBoundary=data_subnet,
    performanceMode="generalPurpose",
    throughputMode="bursting",
    encrypted=False,                # optional in reference arch; flagged as finding
    inTransitEncryption=False,      # reference arch mounts without TLS; flagged as finding
    backupEnabled=False,            # not configured in base template
    publiclyAccessible=False,
)

# ElastiCache Memcached — used by the W3 Total Cache WordPress plugin to cache
# database query results. One node per AZ minimum, cross-AZ deployment.
cache = ElastiCacheCluster(
    "WordPress Memcached",
    inBoundary=data_subnet,
    engine="memcached",             # reference arch uses Memcached (not Redis)
    engineVersion="1.6",
    encrypted=False,                # Memcached does not support in-transit TLS in ElastiCache classic
    authEnabled=False,              # Memcached AUTH not available in ElastiCache (SASL optional)
    multiAZ=True,                   # nodes spread across AZs
    publiclyAccessible=False,
)

# ── Static asset offload (optional) ─────────────────────────────────────────
# W3 Total Cache plugin pushes static assets (images, CSS, JS) to S3.
# CloudFront serves the S3 bucket as a second origin.

static_bucket = S3Bucket(
    "WordPress Static Assets",
    inBoundary=data_subnet,
    encrypted=True,
    blockPublicAccess=True,         # access gated through CloudFront OAC
    versioned=False,                # static assets — versioning not required
    loggingEnabled=False,           # not configured in reference arch
    storesSensitiveData=False,
)

# EFS metrics Lambda — runs every minute, reads EFS burst credit metrics,
# and publishes custom CloudWatch metrics. Also handles EFS data initialisation
# (terminates the temporary EC2 data-loader instance after first run).
efs_monitor = LambdaFunction(
    "EFS Monitor Lambda",
    inBoundary=web_subnet,
    environment="production",
    vpcEnabled=False,               # reference arch deploys Lambda outside VPC
    codeSigningEnabled=False,
    xrayTracingEnabled=False,
    usesEnvironmentVariables=True,  # EFS ID and CloudWatch namespace passed as env vars
    hasSecretsManagerIntegration=False,
    dlqConfigured=False,
)

# ── Dataflows ────────────────────────────────────────────────────────────────

# Edge flows
Dataflow(end_user,       cdn,            "HTTPS (viewer request)")
Dataflow(cdn,            alb,            "HTTPS (origin request to ALB)")
Dataflow(cdn,            static_bucket,  "HTTPS (origin fetch, OAC-signed)")

# ALB → application tier
Dataflow(alb,            wordpress_asg,  "HTTP port 80 (WebSecurityGroup)")

# Application tier internal flows
Dataflow(wordpress_asg,  db,             "TCP 3306 MySQL (DatabaseSecurityGroup)")
Dataflow(wordpress_asg,  cache,          "TCP 11211 Memcached (ElastiCacheSecurityGroup)")
Dataflow(wordpress_asg,  efs,            "TCP 2049 NFS (EfsSecurityGroup)")
Dataflow(wordpress_asg,  static_bucket,  "HTTPS S3 PutObject (W3TC plugin upload)")

# Admin / operational flows
Dataflow(admin,          bastion,        "TCP 22 SSH (BastionSecurityGroup)")
Dataflow(bastion,        wordpress_asg,  "TCP 22 SSH (WebSecurityGroup allows Bastion SG)")
Dataflow(bastion,        efs,            "TCP 22 SSH (EfsSecurityGroup allows Bastion SG)")

# Monitoring
Dataflow(efs_monitor,    efs,            "EFS describe / metrics read")

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tm.process()
