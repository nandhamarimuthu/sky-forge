"""Build the bundled one-month AWS data dumps used by the demo projects.

The files use the exact shapes produced by AWS exports (Cost & Usage Report CSV columns and `aws ... describe-*`
/ `get-metric-statistics` JSON), so the same adapter reads a real export from scripts/export_aws_dump.sh.

Usage: python scripts/build_sample_aws_dumps.py   (deterministic; rewrites fixtures/aws/*)
"""

from __future__ import annotations

import csv
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "aws"
PERIOD_START = date(2026, 9, 22)
DAYS = 30

EC2_HOURLY = {"t3.micro": 0.0118, "t3.medium": 0.0472, "t3.large": 0.0944, "m5.large": 0.111, "m5.xlarge": 0.222,
              "m5.2xlarge": 0.444, "c5.xlarge": 0.202, "c5.2xlarge": 0.404, "r5.xlarge": 0.296}
RDS_HOURLY = {"db.t3.medium": 0.08, "db.m5.large": 0.198, "db.m5.xlarge": 0.396, "db.r5.large": 0.28,
              "db.r5.xlarge": 0.56}
EBS_GB_MONTH = {"gp2": 0.116, "gp3": 0.0928, "io1": 0.145}
REGION_PREFIX = {"eu-west-2": "EUW2", "eu-west-1": "EU", "us-east-1": "USE1"}

CUR_COLUMNS = ["identity/LineItemId", "bill/BillingPeriodStartDate", "lineItem/UsageAccountId",
               "lineItem/LineItemType", "lineItem/UsageStartDate", "lineItem/UsageEndDate", "lineItem/ProductCode",
               "lineItem/UsageType", "lineItem/Operation", "lineItem/ResourceId", "lineItem/UsageAmount",
               "lineItem/UnblendedRate", "lineItem/UnblendedCost", "product/ProductName", "product/region",
               "pricing/unit", "resourceTags/user:Project", "resourceTags/user:Environment"]
PRODUCT_NAMES = {"AmazonEC2": "Amazon Elastic Compute Cloud", "AmazonRDS": "Amazon Relational Database Service",
                 "AmazonS3": "Amazon Simple Storage Service", "AWSLambda": "AWS Lambda",
                 "AWSELB": "Elastic Load Balancing", "AmazonCloudWatch": "AmazonCloudWatch",
                 "AWSDataTransfer": "AWS Data Transfer"}


def iso(d: date, h: int = 0) -> str:
    return datetime(d.year, d.month, d.day, h).strftime("%Y-%m-%dT%H:%M:%SZ")


class Dump:
    def __init__(self, name: str, account: str, region: str, tag: str, seed: int, description: str):
        self.name, self.account, self.region, self.tag = name, account, region, tag
        self.r = random.Random(seed)  # noqa: S311 - deterministic sample data, not security-relevant
        self.pre = REGION_PREFIX[region]
        self.description = description
        self.cur: list[dict[str, str]] = []
        self.metrics: list[dict] = []
        self.instances: list[dict] = []
        self.volumes: list[dict] = []
        self.snapshots: list[dict] = []
        self.dbs: list[dict] = []
        self.nats: list[dict] = []
        self.lbs: list[dict] = []
        self.lambdas: list[dict] = []
        self.buckets: list[dict] = []
        self.spikes: dict[tuple[str, int], float] = {}

    def days(self) -> list[date]:
        return [PERIOD_START + timedelta(days=i) for i in range(DAYS)]

    def tags(self, name: str, env: str = "prod") -> list[dict[str, str]]:
        t = [{"Key": "Name", "Value": name}, {"Key": "Environment", "Value": env}, {"Key": "ManagedBy",
                                                                                    "Value": "terraform"}]
        if self.tag:
            t.append({"Key": "Project", "Value": self.tag})
        return t

    def line(self, d: date, product: str, usage_type: str, op: str, rid: str, amount: float, rate: float,
             unit: str, env: str = "prod", cost: float | None = None) -> None:
        cost = round(amount * rate if cost is None else cost, 6)
        self.cur.append({
            "identity/LineItemId": f"{self.r.getrandbits(64):016x}", "bill/BillingPeriodStartDate": iso(PERIOD_START),
            "lineItem/UsageAccountId": self.account, "lineItem/LineItemType": "Usage",
            "lineItem/UsageStartDate": iso(d), "lineItem/UsageEndDate": iso(d + timedelta(days=1)),
            "lineItem/ProductCode": product, "lineItem/UsageType": usage_type, "lineItem/Operation": op,
            "lineItem/ResourceId": rid, "lineItem/UsageAmount": f"{amount:.6f}", "lineItem/UnblendedRate": f"{rate:.6f}",
            "lineItem/UnblendedCost": f"{cost:.6f}", "product/ProductName": PRODUCT_NAMES.get(product, product),
            "product/region": self.region, "pricing/unit": unit, "resourceTags/user:Project": self.tag,
            "resourceTags/user:Environment": env})

    def metric(self, ns: str, name: str, dims: list[tuple[str, str]], stat: str, unit: str,
               values: list[float], maxima: list[float] | None = None) -> None:
        pts = []
        for i, d in enumerate(self.days()):
            p = {"Timestamp": iso(d), stat: round(values[i], 4), "Unit": unit}
            if maxima:
                p["Maximum"] = round(maxima[i], 4)
            pts.append(p)
        self.metrics.append({"Namespace": ns, "MetricName": name, "Dimensions": [{"Name": k, "Value": v}
                                                                                 for k, v in dims],
                             "Statistic": stat, "Unit": unit, "Label": name, "Datapoints": pts})

    def series(self, lo: float, hi: float) -> list[float]:
        return [self.r.uniform(lo, hi) for _ in range(DAYS)]

    # ------------------------------------------------------------------ resources
    def ec2(self, name: str, itype: str, cpu: tuple[float, float], net_mb: tuple[float, float], az: str = "a",
            env: str = "prod", public_ip: bool = False, root_gb: int = 100, root_type: str = "gp2") -> str:
        iid = f"i-{self.r.getrandbits(68):017x}"
        inst = {"InstanceId": iid, "InstanceType": itype, "ImageId": "ami-0c1c30571d2dae5c9",
                "State": {"Code": 16, "Name": "running"}, "LaunchTime": iso(PERIOD_START - timedelta(
                    days=self.r.randint(60, 500))), "Placement": {"AvailabilityZone": f"{self.region}{az}"},
                "PrivateIpAddress": f"10.0.{self.r.randint(1, 250)}.{self.r.randint(2, 250)}",
                "Tags": self.tags(name, env), "Architecture": "x86_64", "PlatformDetails": "Linux/UNIX"}
        if public_ip:
            inst["PublicIpAddress"] = f"18.{self.r.randint(130, 170)}.{self.r.randint(1, 250)}.{self.r.randint(1, 250)}"
        self.instances.append(inst)
        cpu_avg = self.series(*cpu)
        self.metric("AWS/EC2", "CPUUtilization", [("InstanceId", iid)], "Average", "Percent", cpu_avg,
                    [min(100, v * self.r.uniform(1.4, 2.2)) for v in cpu_avg])
        self.metric("AWS/EC2", "NetworkIn", [("InstanceId", iid)], "Sum", "Bytes",
                    [v * 1e6 for v in self.series(*net_mb)])
        for d in self.days():
            self.line(d, "AmazonEC2", f"{self.pre}-BoxUsage:{itype}", "RunInstances", iid, 24, EC2_HOURLY[itype],
                      "Hrs", env)
        self.volume(f"{name}-root", root_gb, root_type, attached_to=iid, env=env)
        return iid

    def volume(self, name: str, size: int, vtype: str, attached_to: str | None, created_days_ago: int = 200,
               env: str = "prod") -> str:
        vid = f"vol-{self.r.getrandbits(68):017x}"
        self.volumes.append({"VolumeId": vid, "Size": size, "VolumeType": vtype,
                             "State": "in-use" if attached_to else "available",
                             "CreateTime": iso(PERIOD_START - timedelta(days=created_days_ago)),
                             "AvailabilityZone": f"{self.region}a", "Encrypted": vtype != "gp2",
                             "Attachments": [{"InstanceId": attached_to, "Device": "/dev/xvda", "State": "attached"}]
                             if attached_to else [], "Tags": self.tags(name, env)})
        for d in self.days():
            self.line(d, "AmazonEC2", f"{self.pre}-EBS:VolumeUsage.{vtype}", "CreateVolume-Gp", vid, size / 30,
                      EBS_GB_MONTH[vtype], "GB-Mo", env)
        return vid

    def snapshot(self, name: str, size: int, age_days: int) -> None:
        sid = f"snap-{self.r.getrandbits(68):017x}"
        self.snapshots.append({"SnapshotId": sid, "VolumeSize": size, "State": "completed",
                               "StartTime": iso(PERIOD_START + timedelta(days=DAYS) - timedelta(days=age_days)),
                               "Description": f"Backup of {name}", "Tags": self.tags(name)})
        for d in self.days():
            self.line(d, "AmazonEC2", f"{self.pre}-EBS:SnapshotUsage", "CreateSnapshot", sid, size / 30, 0.053,
                      "GB-Mo")

    def rds(self, ident: str, cls: str, cpu: tuple[float, float], conns: tuple[float, float], storage: int = 200,
            public: bool = False, encrypted: bool = True, multi_az: bool = False) -> None:
        arn = f"arn:aws:rds:{self.region}:{self.account}:db:{ident}"
        self.dbs.append({"DBInstanceIdentifier": ident, "DBInstanceArn": arn, "DBInstanceClass": cls,
                         "Engine": "postgres", "EngineVersion": "15.7", "DBInstanceStatus": "available",
                         "MultiAZ": multi_az, "AllocatedStorage": storage, "StorageType": "gp2",
                         "StorageEncrypted": encrypted, "PubliclyAccessible": public,
                         "TagList": self.tags(ident)})
        self.metric("AWS/RDS", "CPUUtilization", [("DBInstanceIdentifier", ident)], "Average", "Percent",
                    self.series(*cpu))
        self.metric("AWS/RDS", "DatabaseConnections", [("DBInstanceIdentifier", ident)], "Average", "Count",
                    self.series(*conns))
        mult = 2 if multi_az else 1
        for d in self.days():
            self.line(d, "AmazonRDS", f"{self.pre}-InstanceUsage:{cls}", "CreateDBInstance:0014", arn, 24 * mult,
                      RDS_HOURLY[cls], "Hrs")
            self.line(d, "AmazonRDS", f"{self.pre}-RDS:GP2-Storage", "CreateDBInstance:0014", arn, storage / 30,
                      0.133, "GB-Mo")

    def nat(self, name: str, gb_day: tuple[float, float], spike_day: int | None = None, spike_gb: float = 0) -> None:
        nid = f"nat-{self.r.getrandbits(68):017x}"
        self.nats.append({"NatGatewayId": nid, "State": "available", "SubnetId": f"subnet-{self.r.getrandbits(32):08x}",
                          "VpcId": "vpc-0a1b2c3d4e5f60718", "ConnectivityType": "public", "Tags": self.tags(name)})
        gbs = self.series(*gb_day)
        if spike_day is not None:
            gbs[spike_day] += spike_gb
        self.metric("AWS/NATGateway", "BytesOutToDestination", [("NatGatewayId", nid)], "Sum", "Bytes",
                    [g * 1e9 for g in gbs])
        for i, d in enumerate(self.days()):
            self.line(d, "AmazonEC2", f"{self.pre}-NatGateway-Hours", "NatGateway", nid, 24, 0.05, "Hrs")
            self.line(d, "AmazonEC2", f"{self.pre}-NatGateway-Bytes", "NatGateway", nid, gbs[i], 0.05, "GB")

    def alb(self, name: str, req: tuple[float, float]) -> None:
        suffix = f"{self.r.getrandbits(64):016x}"
        arn = f"arn:aws:elasticloadbalancing:{self.region}:{self.account}:loadbalancer/app/{name}/{suffix}"
        self.lbs.append({"LoadBalancerArn": arn, "LoadBalancerName": name, "Type": "application",
                         "Scheme": "internet-facing", "State": {"Code": "active"},
                         "CreatedTime": iso(PERIOD_START - timedelta(days=300)),
                         "Tags": self.tags(name)})
        reqs = self.series(*req)
        self.metric("AWS/ApplicationELB", "RequestCount", [("LoadBalancer", f"app/{name}/{suffix}")], "Sum",
                    "Count", reqs)
        for i, d in enumerate(self.days()):
            self.line(d, "AWSELB", f"{self.pre}-LoadBalancerUsage", "LoadBalancing:Application", arn, 24, 0.0252,
                      "Hrs")
            self.line(d, "AWSELB", f"{self.pre}-LCUUsage", "LoadBalancing:Application", arn,
                      max(0.0, reqs[i] / 25000 * 24 / 24), 0.008, "LCU-Hrs")

    def function(self, name: str, mem: int, monthly_inv: int, dur_ms: float, arch: str = "x86_64",
                 spike_day: int | None = None, spike_factor: float = 1.0) -> None:
        arn = f"arn:aws:lambda:{self.region}:{self.account}:function:{name}"
        self.lambdas.append({"FunctionName": name, "FunctionArn": arn, "Runtime": "python3.11", "MemorySize": mem,
                             "Timeout": 30, "Architectures": [arch], "LastModified": iso(PERIOD_START),
                             "Tags": {"Project": self.tag} if self.tag else {}})
        inv = [monthly_inv / DAYS * self.r.uniform(0.85, 1.15) for _ in range(DAYS)]
        if spike_day is not None:
            inv[spike_day] *= spike_factor
        dur = [dur_ms * self.r.uniform(0.9, 1.1) for _ in range(DAYS)]
        self.metric("AWS/Lambda", "Invocations", [("FunctionName", name)], "Sum", "Count", inv)
        self.metric("AWS/Lambda", "Duration", [("FunctionName", name)], "Average", "Milliseconds", dur)
        price = 0.0000166667 if arch == "x86_64" else 0.0000133334
        for i, d in enumerate(self.days()):
            gbs = inv[i] * dur[i] / 1000 * mem / 1024
            self.line(d, "AWSLambda", f"{self.pre}-Lambda-GB-Second" + ("-ARM" if arch == "arm64" else ""),
                      "Invoke", arn, gbs, price, "Lambda-GB-Second")
            self.line(d, "AWSLambda", f"{self.pre}-Request" + ("-ARM" if arch == "arm64" else ""), "Invoke", arn,
                      inv[i], 0.0000002, "Requests")

    def bucket(self, name: str, size_gb: float, lifecycle: bool, ia_ratio: float | None, acl: str = "private") -> None:
        b: dict = {"Name": name, "CreationDate": iso(PERIOD_START - timedelta(days=700)), "Acl": acl,
                   "LifecycleRules": [{"ID": "expire-old", "Status": "Enabled",
                                       "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}]}] if lifecycle
                   else None, "Tags": {"Project": self.tag} if self.tag else {}}
        if ia_ratio is not None:
            b["StorageClassAnalysis"] = {"infrequent_access_ratio": ia_ratio, "observation_days": 90}
        self.buckets.append(b)
        sizes = [size_gb * (0.97 + 0.03 * i / DAYS) for i in range(DAYS)]
        self.metric("AWS/S3", "BucketSizeBytes", [("BucketName", name), ("StorageType", "StandardStorage")],
                    "Average", "Bytes", [s * 1e9 for s in sizes])
        for i, d in enumerate(self.days()):
            self.line(d, "AmazonS3", f"{self.pre}-TimedStorage-ByteHrs", "StandardStorage", name, sizes[i] / 30,
                      0.024, "GB-Mo")
            self.line(d, "AmazonS3", f"{self.pre}-Requests-Tier1", "PutObject", name, self.r.uniform(2e4, 9e4),
                      0.0000053, "Requests")

    def account_wide(self, cw_daily: float, transfer_gb: tuple[float, float]) -> None:
        for d in self.days():
            self.line(d, "AmazonCloudWatch", f"{self.pre}-CW:MetricMonitorUsage", "MetricStorage", "", cw_daily / 0.3,
                      0.3 / 30 * 30 / 30, "Metrics", cost=cw_daily * self.r.uniform(0.95, 1.05))
            self.line(d, "AWSDataTransfer", f"{self.pre}-DataTransfer-Out-Bytes", "", "",
                      self.r.uniform(*transfer_gb), 0.09, "GB")

    # ------------------------------------------------------------------ write
    def write(self) -> None:
        out = ROOT / self.name
        out.mkdir(parents=True, exist_ok=True)
        end = PERIOD_START + timedelta(days=DAYS - 1)
        manifest = {"account_id": self.account, "region": self.region, "currency": "USD",
                    "period_start": PERIOD_START.isoformat(), "period_end": end.isoformat(),
                    "exported_at": iso(end + timedelta(days=1), 6), "granularity": "DAILY",
                    "project_tag": self.tag, "format": "skyforge-aws-dump/v1",
                    "description": self.description,
                    "files": ["cost_and_usage.csv", "ec2_instances.json", "ebs_volumes.json", "ebs_snapshots.json",
                              "rds_instances.json", "nat_gateways.json", "load_balancers.json",
                              "lambda_functions.json", "s3_buckets.json", "cloudwatch_metrics.json"]}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with (out / "cost_and_usage.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=CUR_COLUMNS)
            w.writeheader()
            w.writerows(self.cur)
        dumps = {"ec2_instances.json": {"Reservations": [{"ReservationId": f"r-{self.r.getrandbits(68):017x}",
                                                         "OwnerId": self.account, "Instances": [i]}
                                                        for i in self.instances]},
                 "ebs_volumes.json": {"Volumes": self.volumes}, "ebs_snapshots.json": {"Snapshots": self.snapshots},
                 "rds_instances.json": {"DBInstances": self.dbs}, "nat_gateways.json": {"NatGateways": self.nats},
                 "load_balancers.json": {"LoadBalancers": self.lbs},
                 "lambda_functions.json": {"Functions": self.lambdas}, "s3_buckets.json": {"Buckets": self.buckets},
                 "cloudwatch_metrics.json": self.metrics}
        for fname, data in dumps.items():
            (out / fname).write_text(json.dumps(data, indent=1) + "\n")
        total = sum(float(r["lineItem/UnblendedCost"]) for r in self.cur)
        print(f"{self.name}: {len(self.cur)} CUR rows, ${total:,.2f} for {DAYS} days, {len(self.metrics)} metric series")


def demo_shop() -> Dump:
    d = Dump("demo-shop", "210987654321", "eu-west-2", "demo-shop", 11,
             "Demo Shop production account — one month of Cost & Usage Report rows with CloudWatch utilisation "
             "and resource inventory, exported with scripts/export_aws_dump.sh format.")
    api = d.ec2("demo-shop-api", "m5.2xlarge", (8, 16), (900, 2400), public_ip=True)
    d.ec2("demo-shop-worker", "m5.xlarge", (45, 72), (300, 900), az="b")
    d.ec2("demo-shop-legacy-batch", "t3.large", (0.3, 1.1), (0.4, 2.5), env="staging")
    d.ec2("demo-shop-bastion", "t3.micro", (0.5, 1.5), (20, 60), public_ip=True, root_gb=20, root_type="gp3")
    d.volume("demo-shop-old-data", 500, "gp2", None, created_days_ago=310)
    d.volume("demo-shop-migration-scratch", 200, "gp3", None, created_days_ago=95)
    d.volume("demo-shop-api-data", 300, "gp2", attached_to=api)
    d.snapshot("demo-shop-db-2025-q3", 400, 410)
    d.snapshot("demo-shop-api-pre-upgrade", 100, 240)
    d.snapshot("demo-shop-api-weekly", 100, 6)
    d.rds("demo-shop-db", "db.r5.xlarge", (2.5, 6.5), (1, 4), public=True, encrypted=False)
    d.nat("demo-shop-nat-a", (35, 80), spike_day=24, spike_gb=1400)
    d.nat("demo-shop-nat-b", (0.05, 0.4))
    d.alb("demo-shop-alb", (60_000, 190_000))
    d.alb("demo-shop-old-alb", (0, 0))
    d.function("demo-shop-image-resize", 1024, 2_100_000, 380, spike_day=24, spike_factor=6.5)
    d.function("demo-shop-order-events", 256, 650_000, 120, arch="arm64")
    d.bucket("demo-shop-assets", 1800, lifecycle=False, ia_ratio=0.72, acl="public-read")
    d.bucket("demo-shop-logs", 4200, lifecycle=True, ia_ratio=0.91)
    d.account_wide(6.5, (40, 70))
    return d


def orders_api() -> Dump:
    d = Dump("orders-api", "345678901234", "eu-west-1", "orders-api", 23,
             "Orders API production account — one month of Cost & Usage Report rows with CloudWatch utilisation "
             "and resource inventory, exported with scripts/export_aws_dump.sh format.")
    d.ec2("orders-api-web", "c5.2xlarge", (7, 15), (1500, 4200), public_ip=True)
    d.ec2("orders-api-worker", "r5.xlarge", (32, 61), (200, 700), az="b")
    d.ec2("orders-api-staging-replica", "m5.large", (0.4, 1.6), (0.2, 3.0), env="staging")
    d.volume("orders-api-reindex-temp", 1000, "io1", None, created_days_ago=140)
    d.snapshot("orders-api-db-launch", 250, 380)
    d.rds("orders-api-db", "db.m5.xlarge", (35, 58), (40, 110), storage=500, multi_az=True)
    d.rds("orders-api-reporting", "db.r5.large", (1.5, 5.0), (0.5, 2.5), storage=300)
    d.nat("orders-api-nat", (60, 110), spike_day=21, spike_gb=2600)
    d.alb("orders-api-alb", (120_000, 320_000))
    d.function("orders-api-invoice-pdf", 1024, 900_000, 1200)
    d.function("orders-api-webhooks", 512, 3_200_000, 85)
    d.bucket("orders-api-exports", 2600, lifecycle=False, ia_ratio=0.85)
    d.account_wide(4.2, (90, 140))
    return d


def shared_platform() -> Dump:
    d = Dump("shared-platform", "456789012345", "eu-west-2", "", 37,
             "Shared platform account (no per-project tags) — default dump for external repositories. One month "
             "of Cost & Usage Report rows with CloudWatch utilisation and resource inventory.")
    d.ec2("platform-api-gateway", "m5.xlarge", (20, 45), (2000, 5000))
    d.ec2("platform-ci-runner", "c5.xlarge", (4, 12), (100, 400))
    d.ec2("platform-old-jenkins", "m5.large", (0.2, 0.9), (0.1, 1.5), env="staging")
    d.volume("platform-jenkins-home", 800, "gp2", None, created_days_ago=420)
    d.snapshot("platform-jenkins-final", 800, 400)
    d.rds("platform-metadata", "db.m5.large", (3, 7), (1, 3))
    d.nat("platform-nat-a", (20, 60), spike_day=18, spike_gb=900)
    d.nat("platform-nat-c", (0.02, 0.2))
    d.alb("platform-public-alb", (200_000, 400_000))
    d.alb("platform-preview-alb", (0, 0))
    d.function("platform-log-shipper", 512, 5_000_000, 140, spike_day=18, spike_factor=5.0)
    d.bucket("platform-artifacts", 3500, lifecycle=False, ia_ratio=0.8)
    d.account_wide(9.0, (60, 120))
    return d


if __name__ == "__main__":
    for builder in (demo_shop, orders_api, shared_platform):
        builder().write()
