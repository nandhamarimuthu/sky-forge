"""Build an AWS data dump from the Terraform in the scanned repository.

The optimiser's only data source: instead of analysing an unrelated sample account, SkyForge
derives the inventory from the resources the repository actually declares, prices them from the on-demand list
price tables, and models utilisation from the declared configuration.

Everything here is *modelled*, not measured, so the generated manifest sets `"simulated": true` and every finding
produced from it is reported with a simulated/estimated data source. The generator is deterministic: the same
Terraform always produces the same dump (values are seeded from the resource address), so scans are reproducible
and diffable.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from app.adapters.aws import pricing
from app.adapters.scanners.terraform import TfResource

FORMAT = "skyforge-aws-dump/v1"
PERIOD_DAYS = 30
METRIC_DAYS = 14
LB_TYPES = ("aws_lb", "aws_alb", "aws_elb", "aws_lb_target_group")
PRODUCT_CODE = {"ec2": "AmazonEC2", "ebs": "AmazonEC2", "snapshot": "AmazonEC2", "rds": "AmazonRDS",
                "natgateway": "AmazonVPC", "elb": "AWSELB", "lambda": "AWSLambda", "s3": "AmazonS3"}


def _seed(address: str) -> int:
    return int(hashlib.sha256(address.encode()).hexdigest()[:8], 16)


def _spread(address: str, low: float, high: float) -> float:
    """Deterministic value in [low, high] derived from the resource address."""
    return round(low + (_seed(address) % 1000) / 999 * (high - low), 2)


def _ident(res: TfResource, *keys: str) -> str:
    for key in keys:
        value = res.value(key)
        if value and not value.startswith(("${", "var.", "local.", "aws_", "data.")):
            return value
    return f"{res.name}".replace("_", "-")


def _int(res: TfResource, key: str, default: int) -> int:
    raw = res.value(key)
    try:
        return int(float(raw)) if raw is not None else default
    except (TypeError, ValueError):
        return default


def _list_values(res: TfResource, key: str) -> list[str]:
    raw = res.attrs.get(key, ("", 0))[0]
    return re.findall(r'"([^"]+)"', raw)


def _tags(res: TfResource, project_tag: str) -> list[dict[str, str]]:
    name = _ident(res, "name", "identifier", "function_name", "bucket")
    tags = [{"Key": "Name", "Value": name}, {"Key": "ManagedBy", "Value": "terraform"},
            {"Key": "TerraformAddress", "Value": res.address},
            {"Key": "skyforge:iac-address", "Value": res.address}]
    if project_tag:
        tags.append({"Key": "Project", "Value": project_tag})
    return tags


def _days(end: date, count: int) -> list[date]:
    return [end - timedelta(days=i) for i in range(count - 1, -1, -1)]


def _metric(resource_id: str, metric: str, unit: str, stat: str, values: list[tuple[date, float]]) -> dict[str, Any]:
    dim = {"ec2": "InstanceId"}.get("", "")  # dimension name is informational only; the adapter reads the value
    return {"MetricName": metric, "Unit": unit, "Statistic": stat,
            "Dimensions": [{"Name": dim or "ResourceId", "Value": resource_id}],
            "Datapoints": [{"Timestamp": f"{d.isoformat()}T00:00:00Z", stat: v} for d, v in values]}


class IacDumpBuilder:
    """Translates Terraform resources into the file layout produced by scripts/export_aws_dump.sh."""

    def __init__(self, tf: list[TfResource], project_tag: str = "", region: str = "eu-west-2",
                 account_id: str = "000000000000"):
        self.tf = tf
        self.project_tag = project_tag
        self.region = region
        self.account_id = account_id
        self.end = date.today()
        self.start = self.end - timedelta(days=PERIOD_DAYS - 1)
        self.metrics: list[dict[str, Any]] = []
        self.cur_rows: list[dict[str, str]] = []
        self.instances: list[dict[str, Any]] = []
        self.volumes: list[dict[str, Any]] = []
        self.snapshots: list[dict[str, Any]] = []
        self.databases: list[dict[str, Any]] = []
        self.nats: list[dict[str, Any]] = []
        self.load_balancers: list[dict[str, Any]] = []
        self.functions: list[dict[str, Any]] = []
        self.buckets: list[dict[str, Any]] = []
        self.attached_volumes: set[str] = set()

    # ------------------------------------------------------------------ cost rows
    def _charge(self, resource_id: str, service: str, monthly: float, tags: list[dict[str, str]]) -> None:
        """Spread a monthly list price across the billing period as daily CUR line items."""
        if monthly <= 0:
            return
        daily = monthly / PERIOD_DAYS
        project = next((t["Value"] for t in tags if t["Key"] == "Project"), "")
        for day in _days(self.end, PERIOD_DAYS):
            self.cur_rows.append({
                "identity/LineItemId": f"{resource_id}-{day.isoformat()}",
                "bill/BillingPeriodStartDate": self.start.isoformat(),
                "lineItem/UsageStartDate": f"{day.isoformat()}T00:00:00Z",
                "lineItem/ProductCode": PRODUCT_CODE.get(service, "AmazonEC2"),
                "lineItem/ResourceId": resource_id,
                "lineItem/UnblendedCost": f"{daily:.6f}",
                "lineItem/CurrencyCode": "USD",
                "product/ProductName": service,
                "product/region": self.region,
                "resourceTags/user:Project": project,
            })

    # ------------------------------------------------------------------ resources
    def _ec2(self, r: TfResource) -> None:
        instance_type = r.value("instance_type") or "t3.micro"
        instance_id = f"i-{_seed(r.address):012x}"[:19]
        tags = _tags(r, self.project_tag)
        public = r.value("associate_public_ip_address") == "true"
        count = max(0, _int(r, "count", 1))
        for n in range(count):
            rid = instance_id if n == 0 else f"{instance_id[:-2]}{n:02x}"
            self.instances.append({
                "InstanceId": rid, "InstanceType": instance_type,
                "Placement": {"AvailabilityZone": f"{self.region}a"}, "State": {"Name": "running"},
                "LaunchTime": f"{self.start.isoformat()}T00:00:00Z",
                "PublicIpAddress": "203.0.113.10" if public else None,
                "Tags": tags if n == 0 else [{**t} for t in tags],
            })
            # Oversized machines are the ones worth rightsizing, so utilisation is modelled from the declared size.
            big = any(s in instance_type for s in ("2xlarge", "4xlarge", "8xlarge", "12xlarge", "16xlarge"))
            avg = _spread(f"{r.address}{n}cpu", 1.0, 4.0) if big else _spread(f"{r.address}{n}cpu", 8.0, 22.0)
            peak = round(avg * (2.0 if big else 1.8), 2)
            self.metrics.append(_metric(rid, "CPUUtilization", "Percent", "Average",
                                        [(d, round(avg + (_seed(f"{rid}{d}") % 100) / 100, 2))
                                         for d in _days(self.end, METRIC_DAYS)]))
            self.metrics.append(_metric(rid, "CPUUtilization", "Percent", "Maximum",
                                        [(d, peak) for d in _days(self.end, METRIC_DAYS)]))
            self.metrics.append(_metric(rid, "NetworkIn", "Bytes", "Average",
                                        [(d, _spread(f"{rid}net", 0.5, 40.0) * 1e6)
                                         for d in _days(self.end, METRIC_DAYS)]))
            monthly = pricing.ec2_monthly(instance_type) or 0.0
            self._charge(rid, "ec2", monthly, tags)
            root = self._root_volume(r, rid, n)
            if root:
                self.volumes.append(root)

    def _root_volume(self, r: TfResource, instance_id: str, n: int) -> dict[str, Any] | None:
        block = re.search(r"root_block_device\s*{([^}]*)}", r.body, re.DOTALL)
        if not block:
            return None
        size = re.search(r"volume_size\s*=\s*(\d+)", block.group(1))
        vtype = re.search(r'volume_type\s*=\s*"([^"]+)"', block.group(1))
        encrypted = re.search(r"encrypted\s*=\s*(true|false)", block.group(1))
        vol_id = f"vol-{_seed(f'{r.address}root{n}'):012x}"[:21]
        volume = {"VolumeId": vol_id, "Size": int(size.group(1)) if size else 8,
                  "VolumeType": vtype.group(1) if vtype else "gp2", "State": "in-use",
                  "CreateTime": f"{self.start.isoformat()}T00:00:00Z",
                  "Encrypted": bool(encrypted and encrypted.group(1) == "true"),
                  "Attachments": [{"InstanceId": instance_id}], "Tags": _tags(r, self.project_tag)}
        self._charge(vol_id, "ebs", volume["Size"] * pricing.EBS_GB_MONTH.get(volume["VolumeType"], 0.116),
                     volume["Tags"])
        return volume

    def _ebs(self, r: TfResource) -> None:
        vol_id = f"vol-{_seed(r.address):012x}"[:21]
        size = _int(r, "size", 100)
        vtype = r.value("type") or "gp2"
        attached = r.address in self.attached_volumes
        tags = _tags(r, self.project_tag)
        self.volumes.append({"VolumeId": vol_id, "Size": size, "VolumeType": vtype,
                             "State": "in-use" if attached else "available",
                             "CreateTime": f"{self.start.isoformat()}T00:00:00Z",
                             "Encrypted": r.value("encrypted") == "true",
                             "Attachments": [{"InstanceId": "i-attached"}] if attached else [], "Tags": tags})
        self._charge(vol_id, "ebs", size * pricing.EBS_GB_MONTH.get(vtype, 0.116), tags)

    def _snapshot(self, r: TfResource) -> None:
        snap_id = f"snap-{_seed(r.address):012x}"[:22]
        size = _int(r, "volume_size", 100)
        age = int(_spread(r.address, 200, 900))
        tags = _tags(r, self.project_tag)
        self.snapshots.append({"SnapshotId": snap_id, "VolumeSize": size, "State": "completed",
                               "StartTime": f"{(self.end - timedelta(days=age)).isoformat()}T00:00:00Z",
                               "Description": r.address, "Tags": tags})
        self._charge(snap_id, "snapshot", size * pricing.SNAPSHOT_GB_MONTH, tags)

    def _rds(self, r: TfResource) -> None:
        ident = _ident(r, "identifier", "name")
        klass = r.value("instance_class") or "db.t3.medium"
        storage = _int(r, "allocated_storage", 100)
        tags = _tags(r, self.project_tag)
        self.databases.append({
            "DBInstanceIdentifier": ident, "DBInstanceClass": klass, "DBInstanceStatus": "available",
            "Engine": r.value("engine") or "postgres", "MultiAZ": r.value("multi_az") == "true",
            "AllocatedStorage": storage, "StorageEncrypted": r.value("storage_encrypted") == "true",
            "PubliclyAccessible": r.value("publicly_accessible") == "true", "TagList": tags})
        idle = any(s in klass for s in ("2xlarge", "4xlarge", "8xlarge"))
        cpu = _spread(f"{r.address}cpu", 1.0, 8.0) if idle else _spread(f"{r.address}cpu", 12.0, 45.0)
        conns = _spread(f"{r.address}conn", 0.0, 4.0) if idle else _spread(f"{r.address}conn", 8.0, 60.0)
        for metric, unit, value in (("CPUUtilization", "Percent", cpu), ("DatabaseConnections", "Count", conns)):
            self.metrics.append(_metric(ident, metric, unit, "Average",
                                        [(d, value) for d in _days(self.end, METRIC_DAYS)]))
        monthly = (pricing.rds_monthly(klass) or 0.0) + storage * 0.127
        if (r.value("storage_type") or "") == "io1":
            monthly += _int(r, "iops", 0) * 0.07
        self._charge(f"db:{ident}", "rds", monthly, tags)

    def _nat(self, r: TfResource) -> None:
        nat_id = f"nat-{_seed(r.address):012x}"[:21]
        tags = _tags(r, self.project_tag)
        self.nats.append({"NatGatewayId": nat_id, "State": "available", "SubnetId": r.value("subnet_id") or "subnet-x",
                          "Tags": tags})
        self.metrics.append(_metric(nat_id, "BytesOutToDestination", "Bytes", "Sum",
                                    [(d, _spread(r.address, 0.05, 3.0) * 1e9)
                                     for d in _days(self.end, METRIC_DAYS)]))
        self._charge(nat_id, "natgateway", pricing.NAT_HOURLY * pricing.HOURS_PER_MONTH, tags)

    def _lb(self, r: TfResource) -> None:
        name = _ident(r, "name")
        key = f"app/{name}/{_seed(r.address):016x}"
        arn = f"arn:aws:elasticloadbalancing:{self.region}:{self.account_id}:loadbalancer/{key}"
        tags = _tags(r, self.project_tag)
        self.load_balancers.append({"LoadBalancerArn": arn, "LoadBalancerName": name,
                                    "Type": r.value("load_balancer_type") or "application",
                                    "State": {"Code": "active"}, "Tags": tags})
        requests = 0.0 if _seed(r.address) % 3 == 0 else _spread(r.address, 1000, 90000)
        self.metrics.append(_metric(key, "RequestCount", "Count", "Sum",
                                    [(d, requests) for d in _days(self.end, METRIC_DAYS)]))
        self._charge(arn, "elb", pricing.ALB_HOURLY * pricing.HOURS_PER_MONTH, tags)

    def _lambda(self, r: TfResource) -> None:
        name = _ident(r, "function_name")
        arch = (_list_values(r, "architectures") or ["x86_64"])[0]
        memory = _int(r, "memory_size", 128)
        timeout = _int(r, "timeout", 3)
        tags = _tags(r, self.project_tag)
        self.functions.append({"FunctionName": name, "Runtime": r.value("runtime") or "python3.9",
                               "MemorySize": memory, "Timeout": timeout, "Architectures": [arch],
                               "Tags": {t["Key"]: t["Value"] for t in tags}})
        invocations = int(_spread(f"{r.address}inv", 20_000, 4_000_000))
        duration = _spread(f"{r.address}dur", 40, min(timeout * 1000, 4000) or 400)
        self.metrics.append(_metric(name, "Invocations", "Count", "Sum",
                                    [(d, invocations / METRIC_DAYS) for d in _days(self.end, METRIC_DAYS)]))
        self.metrics.append(_metric(name, "Duration", "Milliseconds", "Average",
                                    [(d, duration) for d in _days(self.end, METRIC_DAYS)]))
        gb_seconds = invocations * (duration / 1000) * (memory / 1024)
        rate = pricing.LAMBDA_GB_SECOND_ARM if arch == "arm64" else pricing.LAMBDA_GB_SECOND_X86
        self._charge(f"function:{name}", "lambda", gb_seconds * rate, tags)

    def _s3(self, r: TfResource) -> None:
        name = _ident(r, "bucket", "name")
        tags = _tags(r, self.project_tag)
        has_lifecycle = any(o.type in ("aws_s3_bucket_lifecycle_configuration",) and name in o.body for o in self.tf) \
            or "lifecycle_rule" in r.body
        size_gb = _spread(r.address, 40, 4000)
        self.buckets.append({"Name": name, "CreationDate": f"{self.start.isoformat()}T00:00:00Z",
                             "LifecycleRules": [{"ID": "existing"}] if has_lifecycle else [],
                             "Acl": "public-read" if 'acl = "public-read' in r.body else "private",
                             "StorageClassAnalysis": {"infrequent_access_ratio": _spread(f"{r.address}cold", 0.3, 0.8)},
                             "Tags": {t["Key"]: t["Value"] for t in tags}})
        self.metrics.append(_metric(name, "BucketSizeBytes", "Bytes", "Average",
                                    [(d, size_gb * 1e9) for d in _days(self.end, METRIC_DAYS)]))
        self._charge(name, "s3", size_gb * pricing.S3_STANDARD_GB, tags)

    # ------------------------------------------------------------------ build
    def build(self) -> dict[str, Any]:
        self.attached_volumes = {m for r in self.tf if r.type == "aws_volume_attachment"
                                 for m in re.findall(r"aws_ebs_volume\.(\w+)", r.body)}
        self.attached_volumes = {f"aws_ebs_volume.{n}" for n in self.attached_volumes}
        handlers = {"aws_instance": self._ec2, "aws_ebs_volume": self._ebs, "aws_ebs_snapshot": self._snapshot,
                    "aws_db_instance": self._rds, "aws_rds_cluster_instance": self._rds,
                    "aws_nat_gateway": self._nat, "aws_lb": self._lb, "aws_alb": self._lb, "aws_elb": self._lb,
                    "aws_lambda_function": self._lambda, "aws_s3_bucket": self._s3}
        for r in self.tf:
            if r.value("count") == "0":
                continue
            handler = handlers.get(r.type)
            if handler:
                handler(r)
        return {
            "manifest.json": {
                "account_id": self.account_id, "region": self.region, "currency": "USD",
                "period_start": self.start.isoformat(), "period_end": self.end.isoformat(),
                "exported_at": f"{self.end.isoformat()}T00:00:00Z", "granularity": "DAILY",
                "project_tag": self.project_tag, "format": FORMAT, "simulated": True,
                "source": "terraform", "terraform_resources": len(self.tf),
                "description": "Generated from the Terraform in this repository. Inventory and configuration come "
                               "from the committed resources; spend is an on-demand list-price model and "
                               "utilisation is derived from the declared sizing — neither is measured from a real "
                               "AWS account.",
            },
            "ec2_instances.json": {"Reservations": [{"Instances": self.instances}] if self.instances else []},
            "ebs_volumes.json": {"Volumes": self.volumes},
            "ebs_snapshots.json": {"Snapshots": self.snapshots},
            "rds_instances.json": {"DBInstances": self.databases},
            "nat_gateways.json": {"NatGateways": self.nats},
            "load_balancers.json": {"LoadBalancers": self.load_balancers},
            "lambda_functions.json": {"Functions": self.functions},
            "s3_buckets.json": {"Buckets": self.buckets},
            "cloudwatch_metrics.json": self.metrics,
        }


CUR_COLUMNS = ["identity/LineItemId", "bill/BillingPeriodStartDate", "lineItem/UsageStartDate",
               "lineItem/ProductCode", "lineItem/ResourceId", "lineItem/UnblendedCost", "lineItem/CurrencyCode",
               "product/ProductName", "product/region", "resourceTags/user:Project"]


def generate_dump(tf: list[TfResource], dest: Path, project_tag: str = "", region: str = "eu-west-2",
                  account_id: str = "000000000000") -> Path:
    """Write current Terraform inventory, even when empty or no declared resource has a known price."""
    builder = IacDumpBuilder(tf, project_tag, region, account_id)
    files = builder.build()
    dest.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        (dest / name).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    with (dest / "cost_and_usage.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CUR_COLUMNS)
        writer.writeheader()
        writer.writerows(builder.cur_rows)
    return dest
