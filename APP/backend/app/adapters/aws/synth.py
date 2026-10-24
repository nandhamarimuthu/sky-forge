"""Build one-month AWS data dumps in the exact export format read by DumpAwsAdapter.

Two uses:
- `synthesize_from_terraform` — when a project has no real export, simulate a month of CUR rows, inventory and
  CloudWatch metrics for the AWS resources declared in the repository's Terraform (clearly labelled *simulated*).
  Repositories without AWS Terraform resources get no data and the AWS agent is skipped.
- scripts/build_sample_aws_dumps.py — the bundled sample dumps.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from app.adapters.aws import pricing
from app.adapters.scanners.terraform import TfResource

DAYS = 30
EBS_GB_MONTH = {"gp2": 0.116, "gp3": 0.0928, "io1": 0.145, "io2": 0.145, "st1": 0.053, "sc1": 0.0174}
REGION_PREFIX = {"eu-west-2": "EUW2", "eu-west-1": "EU", "us-east-1": "USE1", "us-west-2": "USW2",
                 "eu-central-1": "EUC1", "ap-south-1": "APS3", "ap-southeast-1": "APS1"}
CUR_COLUMNS = ["identity/LineItemId", "bill/BillingPeriodStartDate", "lineItem/UsageAccountId",
               "lineItem/LineItemType", "lineItem/UsageStartDate", "lineItem/UsageEndDate", "lineItem/ProductCode",
               "lineItem/UsageType", "lineItem/Operation", "lineItem/ResourceId", "lineItem/UsageAmount",
               "lineItem/UnblendedRate", "lineItem/UnblendedCost", "product/ProductName", "product/region",
               "pricing/unit", "resourceTags/user:Project", "resourceTags/user:Environment"]
PRODUCT_NAMES = {"AmazonEC2": "Amazon Elastic Compute Cloud", "AmazonRDS": "Amazon Relational Database Service",
                 "AmazonS3": "Amazon Simple Storage Service", "AWSLambda": "AWS Lambda",
                 "AWSELB": "Elastic Load Balancing", "AmazonCloudWatch": "AmazonCloudWatch",
                 "AWSDataTransfer": "AWS Data Transfer"}
SUPPORTED_TF = ("aws_instance", "aws_db_instance", "aws_ebs_volume", "aws_ebs_snapshot", "aws_nat_gateway", "aws_lb",
                "aws_alb", "aws_lambda_function", "aws_s3_bucket")


def iso(d: date, h: int = 0) -> str:
    return datetime(d.year, d.month, d.day, h).strftime("%Y-%m-%dT%H:%M:%SZ")


class DumpBuilder:
    def __init__(self, name: str, account: str, region: str, tag: str, seed: int, description: str,
                 period_start: date):
        self.name, self.account, self.region, self.tag = name, account, region, tag
        self.r = random.Random(seed)  # noqa: S311 - deterministic sample data, not security-relevant
        self.pre = REGION_PREFIX.get(region, "USE1")
        self.description = description
        self.period_start = period_start
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

    def days(self) -> list[date]:
        return [self.period_start + timedelta(days=i) for i in range(DAYS)]

    def tags(self, name: str, env: str = "prod") -> list[dict[str, str]]:
        t = [{"Key": "Name", "Value": name}, {"Key": "Environment", "Value": env},
             {"Key": "ManagedBy", "Value": "terraform"}]
        if self.tag:
            t.append({"Key": "Project", "Value": self.tag})
        return t

    def line(self, d: date, product: str, usage_type: str, op: str, rid: str, amount: float, rate: float,
             unit: str, env: str = "prod", cost: float | None = None) -> None:
        cost = round(amount * rate if cost is None else cost, 6)
        self.cur.append({
            "identity/LineItemId": f"{self.r.getrandbits(64):016x}",
            "bill/BillingPeriodStartDate": iso(self.period_start),
            "lineItem/UsageAccountId": self.account, "lineItem/LineItemType": "Usage",
            "lineItem/UsageStartDate": iso(d), "lineItem/UsageEndDate": iso(d + timedelta(days=1)),
            "lineItem/ProductCode": product, "lineItem/UsageType": usage_type, "lineItem/Operation": op,
            "lineItem/ResourceId": rid, "lineItem/UsageAmount": f"{amount:.6f}",
            "lineItem/UnblendedRate": f"{rate:.6f}", "lineItem/UnblendedCost": f"{cost:.6f}",
            "product/ProductName": PRODUCT_NAMES.get(product, product), "product/region": self.region,
            "pricing/unit": unit, "resourceTags/user:Project": self.tag, "resourceTags/user:Environment": env})

    def metric(self, ns: str, name: str, dims: list[tuple[str, str]], stat: str, unit: str,
               values: list[float], maxima: list[float] | None = None) -> None:
        pts = []
        for i, d in enumerate(self.days()):
            p: dict[str, Any] = {"Timestamp": iso(d), stat: round(values[i], 4), "Unit": unit}
            if maxima:
                p["Maximum"] = round(maxima[i], 4)
            pts.append(p)
        self.metrics.append({"Namespace": ns, "MetricName": name,
                             "Dimensions": [{"Name": k, "Value": v} for k, v in dims],
                             "Statistic": stat, "Unit": unit, "Label": name, "Datapoints": pts})

    def series(self, lo: float, hi: float) -> list[float]:
        return [self.r.uniform(lo, hi) for _ in range(DAYS)]

    # ------------------------------------------------------------------ resources
    def ec2(self, name: str, itype: str, cpu: tuple[float, float], net_mb: tuple[float, float], az: str = "a",
            env: str = "prod", public_ip: bool = False, root_gb: int = 100, root_type: str = "gp2") -> str:
        iid = f"i-{self.r.getrandbits(68):017x}"
        inst = {"InstanceId": iid, "InstanceType": itype, "ImageId": "ami-0c1c30571d2dae5c9",
                "State": {"Code": 16, "Name": "running"},
                "LaunchTime": iso(self.period_start - timedelta(days=self.r.randint(60, 500))),
                "Placement": {"AvailabilityZone": f"{self.region}{az}"},
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
        rate = pricing.EC2_HOURLY.get(itype, 0.1)
        for d in self.days():
            self.line(d, "AmazonEC2", f"{self.pre}-BoxUsage:{itype}", "RunInstances", iid, 24, rate, "Hrs", env)
        self.volume(f"{name}-root", root_gb, root_type, attached_to=iid, env=env)
        return iid

    def volume(self, name: str, size: int, vtype: str, attached_to: str | None, created_days_ago: int = 200,
               env: str = "prod") -> str:
        vid = f"vol-{self.r.getrandbits(68):017x}"
        self.volumes.append({"VolumeId": vid, "Size": size, "VolumeType": vtype,
                             "State": "in-use" if attached_to else "available",
                             "CreateTime": iso(self.period_start - timedelta(days=created_days_ago)),
                             "AvailabilityZone": f"{self.region}a", "Encrypted": vtype != "gp2",
                             "Attachments": [{"InstanceId": attached_to, "Device": "/dev/xvda", "State": "attached"}]
                             if attached_to else [], "Tags": self.tags(name, env)})
        for d in self.days():
            self.line(d, "AmazonEC2", f"{self.pre}-EBS:VolumeUsage.{vtype}", "CreateVolume-Gp", vid, size / 30,
                      EBS_GB_MONTH.get(vtype, 0.1), "GB-Mo", env)
        return vid

    def snapshot(self, name: str, size: int, age_days: int) -> None:
        sid = f"snap-{self.r.getrandbits(68):017x}"
        self.snapshots.append({"SnapshotId": sid, "VolumeSize": size, "State": "completed",
                               "StartTime": iso(self.period_start + timedelta(days=DAYS) - timedelta(days=age_days)),
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
        rate = pricing.RDS_HOURLY.get(cls, 0.2)
        for d in self.days():
            self.line(d, "AmazonRDS", f"{self.pre}-InstanceUsage:{cls}", "CreateDBInstance:0014", arn, 24 * mult,
                      rate, "Hrs")
            self.line(d, "AmazonRDS", f"{self.pre}-RDS:GP2-Storage", "CreateDBInstance:0014", arn, storage / 30,
                      0.133, "GB-Mo")

    def nat(self, name: str, gb_day: tuple[float, float], spike_day: int | None = None, spike_gb: float = 0) -> None:
        nid = f"nat-{self.r.getrandbits(68):017x}"
        self.nats.append({"NatGatewayId": nid, "State": "available",
                          "SubnetId": f"subnet-{self.r.getrandbits(32):08x}",
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
                         "CreatedTime": iso(self.period_start - timedelta(days=300)), "Tags": self.tags(name)})
        reqs = self.series(*req)
        self.metric("AWS/ApplicationELB", "RequestCount", [("LoadBalancer", f"app/{name}/{suffix}")], "Sum",
                    "Count", reqs)
        for i, d in enumerate(self.days()):
            self.line(d, "AWSELB", f"{self.pre}-LoadBalancerUsage", "LoadBalancing:Application", arn, 24, 0.0252,
                      "Hrs")
            self.line(d, "AWSELB", f"{self.pre}-LCUUsage", "LoadBalancing:Application", arn,
                      max(0.0, reqs[i] / 25000), 0.008, "LCU-Hrs")

    def function(self, name: str, mem: int, monthly_inv: int, dur_ms: float, arch: str = "x86_64",
                 spike_day: int | None = None, spike_factor: float = 1.0) -> None:
        arn = f"arn:aws:lambda:{self.region}:{self.account}:function:{name}"
        self.lambdas.append({"FunctionName": name, "FunctionArn": arn, "Runtime": "python3.11", "MemorySize": mem,
                             "Timeout": 30, "Architectures": [arch], "LastModified": iso(self.period_start),
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
        b: dict = {"Name": name, "CreationDate": iso(self.period_start - timedelta(days=700)), "Acl": acl,
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
            self.line(d, "AmazonCloudWatch", f"{self.pre}-CW:MetricMonitorUsage", "MetricStorage", "",
                      cw_daily / 0.3, 0.3, "Metrics", cost=cw_daily * self.r.uniform(0.95, 1.05))
            self.line(d, "AWSDataTransfer", f"{self.pre}-DataTransfer-Out-Bytes", "", "",
                      self.r.uniform(*transfer_gb), 0.09, "GB")

    # ------------------------------------------------------------------ write
    def write(self, out: Path, extra_manifest: dict[str, Any] | None = None) -> float:
        out.mkdir(parents=True, exist_ok=True)
        end = self.period_start + timedelta(days=DAYS - 1)
        manifest = {"account_id": self.account, "region": self.region, "currency": "USD",
                    "period_start": self.period_start.isoformat(), "period_end": end.isoformat(),
                    "exported_at": iso(end + timedelta(days=1), 6), "granularity": "DAILY",
                    "project_tag": self.tag, "format": "skyforge-aws-dump/v1", "description": self.description,
                    "files": ["cost_and_usage.csv", "ec2_instances.json", "ebs_volumes.json", "ebs_snapshots.json",
                              "rds_instances.json", "nat_gateways.json", "load_balancers.json",
                              "lambda_functions.json", "s3_buckets.json", "cloudwatch_metrics.json"],
                    **(extra_manifest or {})}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with (out / "cost_and_usage.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=CUR_COLUMNS)
            w.writeheader()
            w.writerows(self.cur)
        files = {"ec2_instances.json": {"Reservations": [{"ReservationId": f"r-{self.r.getrandbits(68):017x}",
                                                         "OwnerId": self.account, "Instances": [i]}
                                                        for i in self.instances]},
                 "ebs_volumes.json": {"Volumes": self.volumes}, "ebs_snapshots.json": {"Snapshots": self.snapshots},
                 "rds_instances.json": {"DBInstances": self.dbs}, "nat_gateways.json": {"NatGateways": self.nats},
                 "load_balancers.json": {"LoadBalancers": self.lbs},
                 "lambda_functions.json": {"Functions": self.lambdas}, "s3_buckets.json": {"Buckets": self.buckets},
                 "cloudwatch_metrics.json": self.metrics}
        for fname, data in files.items():
            (out / fname).write_text(json.dumps(data, indent=1) + "\n")
        return sum(float(r["lineItem/UnblendedCost"]) for r in self.cur)


# ---------------------------------------------------------------------- Terraform → simulated month
def _num(res: TfResource, key: str, default: float) -> float:
    try:
        return float(res.value(key) or default)
    except ValueError:  # variables / expressions
        return default


def _str(res: TfResource, key: str, default: str) -> str:
    v = res.value(key)
    return v if v and re.fullmatch(r"[A-Za-z0-9._:/-]+", v) else default


def _bool(res: TfResource, key: str) -> bool:
    return (res.value(key) or "").lower() == "true"


def aws_resources(tf: list[TfResource]) -> list[TfResource]:
    return [r for r in tf if r.type in SUPPORTED_TF]


def synthesize_from_terraform(tf: list[TfResource], out: Path, *, tag: str, account: str, region: str,
                              seed_key: str, today: date | None = None) -> int:
    """Write a simulated one-month dump for the Terraform-declared AWS resources. Returns the resource count."""
    resources = aws_resources(tf)
    if not resources:
        return 0
    seed = int(hashlib.sha256(seed_key.encode()).hexdigest()[:12], 16)
    start = (today or date.today()) - timedelta(days=DAYS)
    b = DumpBuilder(out.name, account, region, tag, seed, "Simulated from the repository's Terraform: one month of "
                    "Cost & Usage Report rows, inventory and CloudWatch utilisation for each declared AWS resource.",
                    start)
    prefix = tag or "app"
    # Utilisation profiles give each resource a believable, reproducible story.
    profiles = {"busy": ((45, 75), (800, 2500)), "normal": ((18, 40), (300, 1200)),
                "oversized": ((4, 12), (100, 600)), "idle": ((0.2, 1.4), (0.1, 3))}
    spike_target = b.r.randrange(len(resources))
    spike_day = b.r.randint(DAYS // 2, DAYS - 3)
    attached = {m.group(1) for r in tf if r.type == "aws_volume_attachment"
                for m in [re.search(r"aws_ebs_volume\.([A-Za-z0-9_-]+)", r.body)] if m}
    # Real accounts almost always have at least one over-provisioned box; make sure the month reflects that.
    forced = next((i for i, r in enumerate(resources) if r.type in ("aws_instance", "aws_db_instance")), -1)
    for i, r in enumerate(resources):
        name = f"{prefix}-{r.name}"
        roll = b.r.random() if i != forced else 0.3
        if r.type == "aws_instance":
            prof = "idle" if roll < 0.2 else "oversized" if roll < 0.55 else "normal" if roll < 0.85 else "busy"
            cpu, net = profiles[prof]
            b.ec2(name, _str(r, "instance_type", "t3.medium"), cpu, net, public_ip=_bool(r, "associate_public_ip_address"),
                  root_gb=int(_num(r, "volume_size", 50)), root_type="gp2")
        elif r.type == "aws_db_instance":
            low = roll < 0.5
            b.rds(_str(r, "identifier", name), _str(r, "instance_class", "db.t3.medium"),
                  (1.5, 6) if low else (25, 55), (0.5, 3) if low else (30, 120),
                  storage=int(_num(r, "allocated_storage", 100)), public=_bool(r, "publicly_accessible"),
                  encrypted=_bool(r, "storage_encrypted"), multi_az=_bool(r, "multi_az"))
        elif r.type == "aws_ebs_volume":
            b.volume(name, int(_num(r, "size", 100)), _str(r, "type", "gp2"),
                     attached_to=None if r.name not in attached else "i-attached", created_days_ago=b.r.randint(40, 400))
        elif r.type == "aws_ebs_snapshot":
            b.snapshot(name, int(_num(r, "volume_size", 100)), b.r.randint(30, 420))
        elif r.type == "aws_nat_gateway":
            b.nat(name, (0.05, 0.5) if roll < 0.3 else (20, 90), spike_day if i == spike_target else None,
                  b.r.uniform(600, 2000))
        elif r.type in ("aws_lb", "aws_alb"):
            b.alb(name[:32], (0, 0) if roll < 0.25 else (40_000, 250_000))
        elif r.type == "aws_lambda_function":
            arch = "arm64" if "arm64" in r.body else "x86_64"
            b.function(_str(r, "function_name", name), int(_num(r, "memory_size", 512)),
                       b.r.randint(200_000, 4_000_000), b.r.uniform(80, 900), arch,
                       spike_day if i == spike_target else None, b.r.uniform(3, 7))
        elif r.type == "aws_s3_bucket":
            b.bucket(_str(r, "bucket", name), b.r.uniform(50, 3000), lifecycle=roll < 0.3,
                     ia_ratio=round(b.r.uniform(0.4, 0.95), 2), acl=_str(r, "acl", "private"))
    b.account_wide(b.r.uniform(1.5, 6), (10, 80))
    b.write(out, {"synthetic": True, "source": "terraform"})
    return len(resources)
