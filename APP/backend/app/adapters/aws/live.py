"""Live, read-only AWS adapter using boto3. Only Describe*/Get*/List* calls are made.

Missing permissions, throttling or unavailable data are recorded in `report.missing_evidence` instead of guessed.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from app.adapters.aws import pricing
from app.adapters.aws.base import AdapterReport, CostSeries, MetricSeries, Resource

log = logging.getLogger(__name__)


class LiveAwsAdapter:
    def __init__(self, profile: str | None, regions: list[str], region_allowlist: list[str],
                 service_allowlist: list[str], project_tag: str, cost_explorer: bool = True):
        import boto3
        from botocore.config import Config

        self.regions = [r for r in regions if r in region_allowlist]
        self.services = set(service_allowlist)
        self.project_tag = project_tag
        self.cost_explorer = cost_explorer and "ce" in self.services
        self.report = AdapterReport(mode="live", simulated=False)
        if not self.regions:
            self.report.errors.append("No requested region is in the region allowlist")
        self._session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self._cfg = Config(retries={"max_attempts": 5, "mode": "adaptive"}, read_timeout=20, connect_timeout=10)

    def _client(self, svc: str, region: str) -> Any:
        return self._session.client(svc, region_name=region, config=self._cfg)

    def _guard(self, what: str, fn: Any) -> Any:
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            self.report.missing_evidence.append(f"{what}: {code}")
        except BotoCoreError as exc:
            self.report.errors.append(f"{what}: {type(exc).__name__}")
        return None

    def _tag_filter(self) -> list[dict[str, Any]]:
        return [{"Name": "tag:Project", "Values": [self.project_tag]}] if self.project_tag else []

    def inventory(self) -> list[Resource]:
        out: list[Resource] = []
        for region in self.regions:
            if "ec2" in self.services:
                ec2 = self._client("ec2", region)
                pages = self._guard("ec2:DescribeInstances", lambda c=ec2: list(
                    c.get_paginator("describe_instances").paginate(Filters=self._tag_filter())))
                for page in pages or []:
                    for resv in page.get("Reservations", []):
                        for inst in resv.get("Instances", []):
                            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                            it = inst.get("InstanceType", "")
                            out.append(Resource(inst["InstanceId"], "ec2", region, it, inst["State"]["Name"],
                                                tags.get("Name", inst["InstanceId"]), tags,
                                                {"launch_time": str(inst.get("LaunchTime"))},
                                                pricing.ec2_monthly(it)))
            if "ebs" in self.services:
                ec2 = self._client("ec2", region)
                vols = self._guard("ec2:DescribeVolumes", lambda c=ec2: list(
                    c.get_paginator("describe_volumes").paginate(Filters=self._tag_filter())))
                for page in vols or []:
                    for v in page.get("Volumes", []):
                        vt = v.get("VolumeType", "gp2")
                        out.append(Resource(v["VolumeId"], "ebs", region, vt, v["State"], v["VolumeId"],
                                            {t["Key"]: t["Value"] for t in v.get("Tags", [])},
                                            {"size_gb": v["Size"], "created": str(v.get("CreateTime"))},
                                            round(v["Size"] * pricing.EBS_GB_MONTH.get(vt, 0.1), 2)))
            if "rds" in self.services:
                rds = self._client("rds", region)
                dbs = self._guard("rds:DescribeDBInstances", lambda c=rds: c.describe_db_instances())
                for db in (dbs or {}).get("DBInstances", []):
                    cls = db["DBInstanceClass"]
                    out.append(Resource(db["DBInstanceIdentifier"], "rds", region, cls, db["DBInstanceStatus"],
                                        db["DBInstanceIdentifier"], {}, {"engine": db.get("Engine"),
                                                                          "multi_az": db.get("MultiAZ")},
                                        pricing.rds_monthly(cls)))
        return out

    def metrics(self, resource: Resource, days: int = 14) -> list[MetricSeries]:
        if "cloudwatch" not in self.services:
            return []
        ns, dim = {"ec2": ("AWS/EC2", "InstanceId"), "rds": ("AWS/RDS", "DBInstanceIdentifier")}.get(
            resource.service, (None, None))
        if not ns:
            return []
        cw = self._client("cloudwatch", resource.region)
        end = datetime.now(UTC)
        data = self._guard("cloudwatch:GetMetricStatistics", lambda: cw.get_metric_statistics(
            Namespace=ns, MetricName="CPUUtilization", Dimensions=[{"Name": dim, "Value": resource.id}],
            StartTime=end - timedelta(days=days), EndTime=end, Period=86400, Statistics=["Average"]))
        if not data or not data.get("Datapoints"):
            self.report.missing_evidence.append(f"No CPUUtilization datapoints for {resource.id}")
            return []
        pts = sorted((d["Timestamp"].date().isoformat(), round(d["Average"], 2)) for d in data["Datapoints"])
        return [MetricSeries(resource.id, "CPUUtilization", "Percent", "1d", pts)]

    def cost(self, days: int = 90) -> CostSeries | None:
        if not self.cost_explorer:
            self.report.missing_evidence.append("Cost Explorer disabled or not allowlisted")
            return None
        ce = self._session.client("ce", region_name="us-east-1", config=self._cfg)
        end = datetime.now(UTC).date()
        start = end - timedelta(days=days)
        flt = {"Tags": {"Key": "Project", "Values": [self.project_tag]}} if self.project_tag else None
        kwargs: dict[str, Any] = {"TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
                                  "Granularity": "DAILY", "Metrics": ["UnblendedCost"],
                                  "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}]}
        if flt:
            kwargs["Filter"] = flt
        data = self._guard("ce:GetCostAndUsage", lambda: ce.get_cost_and_usage(**kwargs))
        if not data:
            return None
        by_service: dict[str, list[tuple[str, float]]] = {}
        for day in data.get("ResultsByTime", []):
            for g in day.get("Groups", []):
                by_service.setdefault(g["Keys"][0], []).append(
                    (day["TimePeriod"]["Start"], round(float(g["Metrics"]["UnblendedCost"]["Amount"]), 2)))
        return CostSeries("DAILY", "USD", start.isoformat(), end.isoformat(), by_service, measured=True)
