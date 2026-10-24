"""AWS data-dump adapter: reads a one-month export of a real account (CUR CSV + AWS CLI JSON outputs).

Expected files (see scripts/export_aws_dump.sh, which produces them with read-only AWS CLI calls):
  manifest.json                account, region, billing period, export time
  cost_and_usage.csv           Cost & Usage Report rows (lineItem/*, product/*, resourceTags/*)
  ec2_instances.json           aws ec2 describe-instances
  ebs_volumes.json             aws ec2 describe-volumes
  ebs_snapshots.json           aws ec2 describe-snapshots --owner-ids self
  rds_instances.json           aws rds describe-db-instances
  nat_gateways.json            aws ec2 describe-nat-gateways
  load_balancers.json          aws elbv2 describe-load-balancers (+ Tags)
  lambda_functions.json        aws lambda list-functions
  s3_buckets.json              aws s3api list-buckets (+ lifecycle / storage-class-analysis per bucket)
  cloudwatch_metrics.json      aws cloudwatch get-metric-statistics results, one entry per metric
Missing files are reported as missing evidence; nothing is guessed.
"""

from __future__ import annotations

import csv
import json
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from app.adapters.aws.base import AdapterReport, CostSeries, MetricSeries, Resource

MAX_FILE_BYTES = 60 * 1024 * 1024
DUMP_FILES = ("manifest.json", "cost_and_usage.csv", "ec2_instances.json", "ebs_volumes.json", "ebs_snapshots.json",
              "rds_instances.json", "nat_gateways.json", "load_balancers.json", "lambda_functions.json",
              "s3_buckets.json", "cloudwatch_metrics.json")
SERVICE_NAMES = {"AmazonEC2": "Amazon EC2", "AmazonRDS": "Amazon RDS", "AmazonS3": "Amazon S3",
                 "AWSLambda": "AWS Lambda", "AmazonVPC": "Amazon VPC", "AWSELB": "Elastic Load Balancing",
                 "AmazonCloudWatch": "Amazon CloudWatch", "AWSDataTransfer": "Data Transfer",
                 "AmazonDynamoDB": "Amazon DynamoDB", "AmazonElastiCache": "Amazon ElastiCache"}


def _tags(items: list[dict[str, str]] | None) -> dict[str, str]:
    return {t.get("Key", ""): t.get("Value", "") for t in (items or [])}


def _day(ts: str) -> str:
    return ts[:10]


class DumpAwsAdapter:
    def __init__(self, dump_dir: Path, project_tag: str = "", iac_hints: list[dict] | None = None):
        self.dir = dump_dir
        self.project_tag = project_tag
        self.iac_hints = iac_hints or []
        self.report = AdapterReport(mode="dump", simulated=False)
        self._inventory: list[Resource] | None = None
        self._metrics: dict[str, list[MetricSeries]] | None = None
        self._cur: list[dict[str, str]] | None = None
        self.manifest: dict[str, Any] = self._json("manifest.json") or {}
        # Dumps modelled from the repository's Terraform declare themselves simulated; real exports do not.
        self.report.simulated = bool(self.manifest.get("simulated"))
        self.report.meta = {
            "source": self.manifest.get("source") or "data dump", "account_id": self.manifest.get("account_id"),
            "region": self.manifest.get("region"), "period_start": self.manifest.get("period_start"),
            "period_end": self.manifest.get("period_end"), "exported_at": self.manifest.get("exported_at"),
            "description": self.manifest.get("description", ""), "dump": dump_dir.name,
        }

    # ------------------------------------------------------------------ io
    def _path(self, name: str) -> Path | None:
        p = self.dir / name
        if not p.is_file():
            self.report.missing_evidence.append(f"{name} not present in dump")
            return None
        if p.stat().st_size > MAX_FILE_BYTES:
            self.report.errors.append(f"{name} exceeds {MAX_FILE_BYTES // (1024 * 1024)} MB")
            return None
        return p

    def _json(self, name: str) -> Any:
        p = self._path(name)
        if p is None:
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.report.errors.append(f"{name}: invalid JSON ({exc.__class__.__name__})")
            return None

    def _cur_rows(self) -> list[dict[str, str]]:
        if self._cur is None:
            p = self._path("cost_and_usage.csv")
            rows: list[dict[str, str]] = []
            if p is not None:
                with p.open(newline="", encoding="utf-8") as fh:
                    rows = list(csv.DictReader(fh))
            if self.project_tag:
                tagged = [r for r in rows if r.get("resourceTags/user:Project") == self.project_tag]
                if tagged:
                    rows = tagged
                elif rows:
                    self.report.missing_evidence.append(
                        f"No cost rows tagged Project={self.project_tag}; using the whole account")
            self._cur = rows
        return self._cur

    def _in_scope(self, tags: dict[str, str]) -> bool:
        return not self.project_tag or tags.get("Project") == self.project_tag or not self._tag_used()

    def _tag_used(self) -> bool:
        return any(r.get("resourceTags/user:Project") == self.project_tag for r in self._cur_rows())

    # ------------------------------------------------------------------ metrics
    def _metric_index(self) -> dict[str, list[MetricSeries]]:
        if self._metrics is not None:
            return self._metrics
        data = self._json("cloudwatch_metrics.json") or []
        idx: dict[str, list[MetricSeries]] = defaultdict(list)
        for m in data if isinstance(data, list) else data.get("metrics", []):
            dims = {d["Name"]: d["Value"] for d in m.get("Dimensions", [])}
            rid = next(iter(dims.values()), "")
            name, unit = m.get("MetricName", ""), m.get("Unit", "")
            pts_raw = sorted(m.get("Datapoints", []), key=lambda d: d.get("Timestamp", ""))
            stat = m.get("Statistic") or ("Sum" if any("Sum" in d for d in pts_raw) else "Average")
            pts = [(_day(d["Timestamp"]), float(d.get(stat, d.get("Average", 0.0)))) for d in pts_raw]
            # Normalise units to what the analysis expects.
            if name == "NetworkIn":
                name, unit, pts = "NetworkInMB", "Megabytes", [(t, round(v / 1e6, 2)) for t, v in pts]
            elif name == "BytesOutToDestination":
                name, unit, pts = "BytesProcessedGB", "Gigabytes", [(t, round(v / 1e9, 3)) for t, v in pts]
            elif name == "BucketSizeBytes":
                name, unit, pts = "BucketSizeGB", "Gigabytes", [(t, round(v / 1e9, 1)) for t, v in pts]
            idx[rid].append(MetricSeries(rid, name, unit, "1d", pts))
        self._metrics = idx
        return idx

    def metrics(self, resource: Resource, days: int = 30) -> list[MetricSeries]:
        idx = self._metric_index()
        key = resource.config.get("metric_key", resource.id)
        series = [MetricSeries(s.resource_id, s.metric, s.unit, s.period, s.points[-days:]) for s in idx.get(key, [])]
        if not series and resource.service in ("ec2", "rds", "natgateway", "elb"):
            self.report.missing_evidence.append(f"No CloudWatch datapoints for {resource.id}")
        return series

    # ------------------------------------------------------------------ inventory
    def _cost_by_resource(self) -> dict[str, float]:
        out: dict[str, float] = defaultdict(float)
        for r in self._cur_rows():
            rid = r.get("lineItem/ResourceId", "")
            if rid:
                out[rid] += float(r.get("lineItem/UnblendedCost") or 0)
        return out

    def _cost_for(self, *ids: str) -> float | None:
        costs = self._cost_by_resource()
        total, found = 0.0, False
        for rid, v in costs.items():
            if any(i and (rid == i or rid.endswith(i) or rid.endswith(f"/{i}") or rid.endswith(f":{i}")) for i in ids):
                total += v
                found = True
        return round(total, 2) if found else None

    IAC_TAG = "skyforge:iac-address"

    def _link(self, tf_type: str, name: str, ident: str | None = None,
              tags: dict[str, str] | None = None) -> str | None:
        # An explicit address tag (emitted by dumps modelled from Terraform) is authoritative.
        tagged = (tags or {}).get(self.IAC_TAG)
        if tagged:
            return tagged
        for h in self.iac_hints:
            if h.get("type") != tf_type:
                continue
            if ident and h.get("identifier") == ident:
                return str(h["address"])
            if name and (name == h["name"] or name.endswith(f"-{h['name']}")):
                return str(h["address"])
        return None

    def inventory(self) -> list[Resource]:
        if self._inventory is not None:
            return self._inventory
        region = self.manifest.get("region", "unknown")
        res: list[Resource] = []
        for resv in (self._json("ec2_instances.json") or {}).get("Reservations", []):
            for i in resv.get("Instances", []):
                tags = _tags(i.get("Tags"))
                if not self._in_scope(tags):
                    continue
                name = tags.get("Name", i["InstanceId"])
                res.append(Resource(
                    i["InstanceId"], "ec2", i.get("Placement", {}).get("AvailabilityZone", region)[:-1] or region,
                    i["InstanceType"], i.get("State", {}).get("Name", "unknown"), name, tags,
                    {"launch_time": i.get("LaunchTime"), "public_ip": bool(i.get("PublicIpAddress"))},
                    self._cost_for(i["InstanceId"]), self._link("aws_instance", name, None, tags)))
        for v in (self._json("ebs_volumes.json") or {}).get("Volumes", []):
            tags = _tags(v.get("Tags"))
            if not self._in_scope(tags):
                continue
            attached = [a.get("InstanceId") for a in v.get("Attachments", [])]
            res.append(Resource(v["VolumeId"], "ebs", region, v.get("VolumeType", "gp2"), v.get("State", "unknown"),
                                tags.get("Name", v["VolumeId"]), tags,
                                {"size_gb": v.get("Size", 0), "created": v.get("CreateTime"),
                                 "attached_to": attached[0] if attached else None,
                                 "encrypted": v.get("Encrypted", False)},
                                self._cost_for(v["VolumeId"]),
                                self._link("aws_ebs_volume", tags.get("Name", ""), None, tags)))
        end = self.manifest.get("period_end")
        end_dt = datetime.fromisoformat(end) if end else None
        for s in (self._json("ebs_snapshots.json") or {}).get("Snapshots", []):
            tags = _tags(s.get("Tags"))
            if not self._in_scope(tags):
                continue
            started = s.get("StartTime", "")
            age = (end_dt - datetime.fromisoformat(started[:10])).days if end_dt and started else 0
            res.append(Resource(s["SnapshotId"], "snapshot", region, "ebs-snapshot", s.get("State", "completed"),
                                tags.get("Name", s.get("Description", s["SnapshotId"]))[:80], tags,
                                {"size_gb": s.get("VolumeSize", 0), "age_days": age},
                                self._cost_for(s["SnapshotId"])))
        for db in (self._json("rds_instances.json") or {}).get("DBInstances", []):
            tags = _tags(db.get("TagList"))
            if not self._in_scope(tags):
                continue
            ident = db["DBInstanceIdentifier"]
            res.append(Resource(ident, "rds", region, db["DBInstanceClass"], db.get("DBInstanceStatus", "unknown"),
                                ident, tags, {"engine": db.get("Engine"), "multi_az": db.get("MultiAZ"),
                                              "storage_gb": db.get("AllocatedStorage"),
                                              "encrypted": db.get("StorageEncrypted"),
                                              "public": db.get("PubliclyAccessible")},
                                self._cost_for(f"db:{ident}", ident), self._link("aws_db_instance", ident, ident, tags)))
        for n in (self._json("nat_gateways.json") or {}).get("NatGateways", []):
            tags = _tags(n.get("Tags"))
            if not self._in_scope(tags):
                continue
            res.append(Resource(n["NatGatewayId"], "natgateway", region, "nat-gateway", n.get("State", "unknown"),
                                tags.get("Name", n["NatGatewayId"]), tags, {"subnet": n.get("SubnetId")},
                                self._cost_for(n["NatGatewayId"]),
                                self._link("aws_nat_gateway", tags.get("Name", ""), None, tags)))
        for lb in (self._json("load_balancers.json") or {}).get("LoadBalancers", []):
            tags = _tags(lb.get("Tags"))
            if not self._in_scope(tags):
                continue
            arn = lb["LoadBalancerArn"]
            key = arn.split("loadbalancer/", 1)[-1]
            res.append(Resource(key, "elb", region, lb.get("Type", "application"),
                                lb.get("State", {}).get("Code", "unknown"), lb.get("LoadBalancerName", key), tags,
                                {"metric_key": key}, self._cost_for(arn, key),
                                self._link("aws_lb", lb.get("LoadBalancerName", ""), None, tags)))
        idx = self._metric_index()
        for fn in (self._json("lambda_functions.json") or {}).get("Functions", []):
            tags = fn.get("Tags") or {}
            if not self._in_scope(tags):
                continue
            name = fn["FunctionName"]
            series = {s.metric: s for s in idx.get(name, [])}
            inv = sum(v for _, v in series["Invocations"].points) if "Invocations" in series else None
            dur = (statistics.fmean(v for _, v in series["Duration"].points)
                   if "Duration" in series and series["Duration"].points else None)
            if inv is None:
                self.report.missing_evidence.append(f"No Invocations metric for Lambda {name}")
            res.append(Resource(name, "lambda", region, (fn.get("Architectures") or ["x86_64"])[0], "active", name,
                                tags, {"memory_mb": fn.get("MemorySize"), "monthly_invocations": int(inv or 0),
                                       "avg_duration_ms": round(dur or 0), "runtime": fn.get("Runtime"),
                                       "architecture": (fn.get("Architectures") or ["x86_64"])[0]},
                                self._cost_for(f"function:{name}", name),
                                self._link("aws_lambda_function", name, None, tags)))
        for b in (self._json("s3_buckets.json") or {}).get("Buckets", []):
            tags = b.get("Tags") or {}
            if not self._in_scope(tags):
                continue
            name = b["Name"]
            size = next((s.points[-1][1] for s in idx.get(name, []) if s.metric == "BucketSizeGB" and s.points), None)
            if size is None:
                self.report.missing_evidence.append(f"No BucketSizeBytes metric for s3://{name}")
            sca = b.get("StorageClassAnalysis") or {}
            cfg: dict[str, Any] = {"size_gb": size or 0, "lifecycle_rules": bool(b.get("LifecycleRules")),
                                   "acl": b.get("Acl")}
            if "infrequent_access_ratio" in sca:
                cfg["objects_not_accessed_90d_ratio"] = sca["infrequent_access_ratio"]
            res.append(Resource(name, "s3", region, "STANDARD", "active", name, tags, cfg, self._cost_for(name),
                                self._link("aws_s3_bucket", name, None, tags)))
        self._inventory = res
        return res

    # ------------------------------------------------------------------ cost
    def cost(self, days: int = 90) -> CostSeries | None:
        rows = self._cur_rows()
        if not rows:
            self.report.missing_evidence.append("No Cost & Usage rows — spend cannot be reported")
            return None
        by: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        for r in rows:
            svc = SERVICE_NAMES.get(r.get("lineItem/ProductCode", ""), r.get("product/ProductName") or
                                    r.get("lineItem/ProductCode", "Other"))
            by[svc][_day(r.get("lineItem/UsageStartDate", ""))] += float(r.get("lineItem/UnblendedCost") or 0)
        dates = sorted({d for s in by.values() for d in s})[-days:]
        series = {svc: [(d, round(vals.get(d, 0.0), 2)) for d in dates] for svc, vals in by.items()}
        return CostSeries("DAILY", self.manifest.get("currency", "USD"), dates[0] if dates else "",
                          dates[-1] if dates else "", series, measured=not self.report.simulated)
