"""Static on-demand list prices (USD, eu-west-2 London, Linux) used for *estimates* only.

These are approximations of public list prices and are labelled as estimates wherever they are used.
"""

from __future__ import annotations

HOURS_PER_MONTH = 730

EC2_HOURLY = {
    "t3.nano": 0.0059, "t3.micro": 0.0118, "t3.small": 0.0236, "t3.medium": 0.0472, "t3.large": 0.0944,
    "t3.xlarge": 0.1888, "t3.2xlarge": 0.3776,
    "m5.large": 0.111, "m5.xlarge": 0.222, "m5.2xlarge": 0.444, "m5.4xlarge": 0.888, "m5.8xlarge": 1.776,
    "c5.large": 0.101, "c5.xlarge": 0.202, "c5.2xlarge": 0.404, "c5.4xlarge": 0.808, "c5.9xlarge": 1.818,
    "r5.large": 0.148, "r5.xlarge": 0.296, "r5.2xlarge": 0.592, "r5.4xlarge": 1.184, "r5.8xlarge": 2.368,
    "m6g.medium": 0.0222, "m6g.large": 0.0888, "m6g.xlarge": 0.1776, "m6g.2xlarge": 0.3552,
    "c6g.large": 0.0808, "c6g.xlarge": 0.1616, "r6g.large": 0.1184, "r6g.xlarge": 0.2368,
}
RDS_HOURLY = {
    "db.t3.micro": 0.02, "db.t3.small": 0.04, "db.t3.medium": 0.08, "db.t3.large": 0.16, "db.t3.xlarge": 0.32,
    "db.t3.2xlarge": 0.64,
    "db.m5.large": 0.198, "db.m5.xlarge": 0.396, "db.m5.2xlarge": 0.792, "db.m5.4xlarge": 1.584,
    "db.r5.large": 0.28, "db.r5.xlarge": 0.56, "db.r5.2xlarge": 1.12, "db.r5.4xlarge": 2.24, "db.r5.8xlarge": 4.48,
    "db.r6g.large": 0.25, "db.r6g.xlarge": 0.50, "db.r6g.2xlarge": 1.00, "db.m6g.large": 0.179,
    "db.m6g.xlarge": 0.358,
}
EBS_GB_MONTH = {"gp2": 0.116, "gp3": 0.0928, "io1": 0.145, "st1": 0.053, "sc1": 0.0174}
SNAPSHOT_GB_MONTH = 0.053
NAT_HOURLY = 0.05
NAT_GB = 0.05
ALB_HOURLY = 0.0252
S3_STANDARD_GB = 0.024
S3_IA_GB = 0.0131
LAMBDA_GB_SECOND_X86 = 0.0000166667
LAMBDA_GB_SECOND_ARM = 0.0000133334

SIZES = ["nano", "micro", "small", "medium", "large", "xlarge", "2xlarge", "4xlarge", "8xlarge"]


def smaller(instance_type: str, prices: dict[str, float]) -> str | None:
    prefix, _, size = instance_type.rpartition(".")
    if size not in SIZES or instance_type not in prices:
        # Without a list price for the current type there is no defensible savings figure to report.
        return None
    idx = SIZES.index(size)
    for s in reversed(SIZES[:idx]):
        cand = f"{prefix}.{s}"
        if cand in prices:
            return cand
    return None


def ratio(from_type: str, to_type: str, prices: dict[str, float]) -> float | None:
    """Price of `to_type` relative to `from_type`, or None when either is unpriced."""
    old, new = prices.get(from_type), prices.get(to_type)
    if not old or new is None:
        return None
    return new / old


def ec2_monthly(t: str) -> float | None:
    p = EC2_HOURLY.get(t)
    return round(p * HOURS_PER_MONTH, 2) if p else None


def rds_monthly(t: str) -> float | None:
    p = RDS_HOURLY.get(t)
    return round(p * HOURS_PER_MONTH, 2) if p else None
