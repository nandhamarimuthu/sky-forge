"""Agent 4 — AWS Cost & Resource Agent (read-only).

Analyses inventory, utilisation metrics and daily cost to find idle/oversized resources, unattached storage and
cost anomalies. Every recommendation carries its evidence, calculation and confidence. Data comes from a one-month
AWS data dump (CUR + CLI export) or the live read-only API. Nothing is ever stopped, resized or deleted.
"""

from __future__ import annotations

import json
import statistics
from typing import Any

from app.adapters.aws import pricing
from app.adapters.aws.base import AwsAdapter, MetricSeries, Resource
from app.adapters.scanners.manifests import unified_diff
from app.adapters.scanners.terraform import TfResource
from app.agents.base import AgentContext, BaseAgent
from app.schemas.agents import AgentResult, ArtifactDraft, FindingDraft, ProposalDraft


def _avg(series: MetricSeries | None) -> float | None:
    return round(statistics.fmean(v for _, v in series.points), 2) if series and series.points else None


def _max(series: MetricSeries | None) -> float | None:
    return round(max(v for _, v in series.points), 2) if series and series.points else None


def detect_anomalies(by_service: dict[str, list[tuple[str, float]]], window: int = 28,
                     z_threshold: float = 3.0) -> list[dict[str, Any]]:
    out = []
    for svc, pts in by_service.items():
        values = [v for _, v in pts]
        win = min(window, max(7, len(values) // 2))
        for i in range(max(win, len(values) - 14), len(values)):
            hist = values[i - win:i]
            if len(hist) < 7:
                continue
            mu, sd = statistics.fmean(hist), statistics.pstdev(hist)
            if sd == 0:
                continue
            z = (values[i] - mu) / sd
            if z >= z_threshold and values[i] - mu > 5:
                out.append({"service": svc, "date": pts[i][0], "cost": values[i], "baseline": round(mu, 2),
                            "z_score": round(z, 1), "excess": round(values[i] - mu, 2)})
    return out


def iac_hints(tf: list[TfResource]) -> list[dict]:
    return [{"type": r.type, "name": r.name, "address": r.address, "instance_type": r.value("instance_type"),
             "instance_class": r.value("instance_class"), "identifier": r.value("identifier")} for r in tf]


class AwsOptimizerAgent(BaseAgent):
    id = "aws_optimizer"
    name = "AWS Cost Optimiser"
    code = "AWS Cost Optimiser"
    description = ("Analyses AWS inventory, utilisation and spend read-only, then recommends right-sizing and "
                   "cleanup savings actions.")
    allowed_tools = frozenset({"repo.read", "terraform.parse", "aws.read"})

    def run(self, ctx: AgentContext) -> AgentResult:
        ws = ctx.tool("repo.read")
        tf = ctx.tool("terraform.parse")(ws)
        adapter: AwsAdapter = ctx.tool("aws.read")(iac_hints(tf), tf)
        simulated = adapter.report.simulated
        dump = adapter.report.mode == "dump"
        source = "simulated" if simulated else "estimated"
        tool_label = ("terraform-generated AWS model" if simulated else
                      {"dump": "aws-data-dump (CUR + CLI export)", "live": "boto3 (read-only)"}.get(
                          adapter.report.mode, "aws-adapter"))
        result = AgentResult(agent_id="aws_optimizer", tools_used=[tool_label])
        pricing_note = ("Terraform-derived model; utilisation and spend are estimates, not AWS measurements"
                        if simulated else
                        "actual spend from the Cost & Usage Report; savings ratios from on-demand list prices"
                        if dump else "on-demand list price estimate (eu-west-2)")
        observed_days = 14
        acct = ctx.project.get("aws") or {}
        scope = {"account_id": acct.get("account_id", "000000000000"), "regions": acct.get("regions", []),
                 "project_tag": acct.get("project_tag", ""), "mode": adapter.report.mode, **adapter.report.meta}
        ctx.log(f"AWS scope: {scope} {'(SIMULATED DATA)' if simulated else ''}")
        inventory = adapter.inventory()
        ctx.progress(0.3, f"Inventory: {len(inventory)} resources")
        tf_by_addr = {r.address: r for r in tf}

        def add(res: Resource, rule: str, sev: str, title: str, savings: float, calc: str, evidence: dict,
                rec: str, confidence: str, savings_type: str = "estimated", proposal: ProposalDraft | None = None,
                risk: str = "") -> None:
            result.findings.append(FindingDraft(
                rule_id=f"aws:{rule}", category="cost", severity=sev,  # type: ignore[arg-type]
                title=title, description=f"{res.service.upper()} {res.id} ({res.type}) in {res.region}. {risk}".strip(),
                target=res.iac_address or res.id, location={"region": res.region, "resource_id": res.id},
                evidence={"scope": scope, "resource": {"id": res.id, "name": res.name, "type": res.type,
                                                       "state": res.state, "tags": res.tags, "config": res.config},
                          "observed": evidence, "period_days": observed_days, "calculation": calc,
                          "savings_type": savings_type, "pricing": pricing_note,
                          "actual_monthly_cost": res.monthly_cost if dump and not simulated else None,
                          "simulated": simulated},
                recommendation=rec, confidence=confidence,  # type: ignore[arg-type]
                data_source=source if savings_type != "hypothetical" else "estimated",  # type: ignore[arg-type]
                estimated_monthly_savings=round(savings, 2), fingerprint_key=f"aws|{rule}|{res.id}",
                proposal=proposal))

        for n, res in enumerate(inventory):
            if n % 5 == 0:
                ctx.check_cancelled()
            m = {s.metric: s for s in adapter.metrics(res)}
            observed_days = max((len(s.points) for s in m.values()), default=observed_days) or observed_days
            if res.service == "ec2" and res.monthly_cost:
                cpu_avg, cpu_max = _avg(m.get("CPUUtilization")), _max(m.get("CPUUtilization"))
                net = _avg(m.get("NetworkInMB"))
                if cpu_avg is None:
                    adapter.report.missing_evidence.append(f"No CPU metrics for {res.id}")
                    continue
                if cpu_avg < 3 and (cpu_max or 0) < 10 and (net is None or net < 5):
                    add(res, "ec2-idle", "high", f"Idle EC2 instance {res.name} ({res.type})", res.monthly_cost,
                        (f"Actual EC2 spend for the period (CUR): ${res.monthly_cost}" if dump else
                         f"{res.type} on-demand ${pricing.EC2_HOURLY.get(res.type, '?')}/h × 730 h"),
                        {"cpu_avg_pct": cpu_avg, "cpu_max_pct": cpu_max, "network_in_mb_per_day": net},
                        "Confirm ownership, snapshot if needed, then stop or terminate.", "high",
                        risk="Stopping an instance interrupts anything still depending on it.")
                elif (cpu_max or 100) < 25:
                    smaller = pricing.smaller(res.type, pricing.EC2_HOURLY)
                    ratio = pricing.ratio(res.type, smaller, pricing.EC2_HOURLY) if smaller else None
                    if smaller and ratio is not None:
                        proposal = self._iac_patch(ws, tf_by_addr.get(res.iac_address or ""), "instance_type",
                                                   res.type, smaller)
                        add(res, "ec2-rightsize", "medium", f"Rightsize {res.name}: {res.type} → {smaller}",
                            res.monthly_cost * (1 - ratio),
                            f"${res.monthly_cost} × (1 − ${pricing.EC2_HOURLY[smaller]}/${pricing.EC2_HOURLY[res.type]} per h)",
                            {"cpu_avg_pct": cpu_avg, "cpu_max_pct": cpu_max},
                            f"Downsize to {smaller} during a maintenance window; monitor p95 CPU for 7 days.",
                            "medium", proposal=proposal, risk="Halving capacity may affect peak latency.")
            elif res.service == "ebs" and res.state == "available":
                add(res, "ebs-unattached", "medium", f"Unattached EBS volume {res.id} ({res.config['size_gb']} GiB)",
                    res.monthly_cost or 0, f"{res.config['size_gb']} GiB × ${pricing.EBS_GB_MONTH[res.type]}/GiB-month",
                    {"state": res.state, "created": res.config.get("created")},
                    "Snapshot (if required) and delete the volume.", "high")
            elif res.service == "ebs" and res.type == "gp2":
                size = res.config["size_gb"]
                saving = size * (pricing.EBS_GB_MONTH["gp2"] - pricing.EBS_GB_MONTH["gp3"])
                if saving >= 2:
                    tf_res = tf_by_addr.get(res.iac_address or "")
                    # Standalone volumes use `type`; a root_block_device inside an instance uses `volume_type`.
                    patch = (self._iac_patch(ws, tf_res, "type", "gp2", "gp3")
                             or self._iac_patch(ws, tf_res, "volume_type", "gp2", "gp3"))
                    add(res, "ebs-gp2-to-gp3", "low", f"Migrate {res.id} from gp2 to gp3", saving,
                        f"{size} GiB × (${pricing.EBS_GB_MONTH['gp2']} − ${pricing.EBS_GB_MONTH['gp3']})",
                        {"size_gb": size}, "Modify volume type to gp3 (online operation).", "high",
                        proposal=patch)
            elif res.service == "snapshot" and res.config.get("age_days", 0) > 180:
                add(res, "snapshot-old", "low", f"Snapshot {res.id} is {res.config['age_days']} days old",
                    res.monthly_cost or 0, f"{res.config['size_gb']} GiB × ${pricing.SNAPSHOT_GB_MONTH}",
                    {"age_days": res.config["age_days"]}, "Apply a snapshot retention policy (DLM).", "medium")
            elif res.service == "rds" and res.monthly_cost:
                cpu, conns = _avg(m.get("CPUUtilization")), _avg(m.get("DatabaseConnections"))
                if cpu is not None and cpu < 10 and (conns or 0) < 5:
                    smaller = pricing.smaller(res.type, pricing.RDS_HOURLY)
                    rds_ratio: float | None = None
                    if not smaller and res.type in pricing.RDS_HOURLY:
                        # Smallest size in its family already: an almost idle DB fits the burstable class.
                        burst = "db.t3." + res.type.rpartition(".")[2]
                        if pricing.RDS_HOURLY.get(burst, 1e9) < pricing.RDS_HOURLY[res.type]:
                            smaller = burst
                    if smaller:
                        rds_ratio = pricing.ratio(res.type, smaller, pricing.RDS_HOURLY)
                    if smaller and rds_ratio is not None:
                        add(res, "rds-rightsize", "medium", f"Downsize RDS {res.name}: {res.type} → {smaller}",
                            res.monthly_cost * (1 - rds_ratio),
                            f"${res.monthly_cost} × (1 − ${pricing.RDS_HOURLY[smaller]}/${pricing.RDS_HOURLY[res.type]} per h)",
                            {"cpu_avg_pct": cpu, "connections_avg": conns},
                            "Downsize during a maintenance window; consider Graviton (r6g).", "medium",
                            proposal=self._iac_patch(ws, tf_by_addr.get(res.iac_address or ""), "instance_class",
                                                     res.type, smaller))
            elif res.service == "natgateway":
                gb = _avg(m.get("BytesProcessedGB"))
                if gb is not None and gb < 1:
                    add(res, "nat-idle", "medium", f"Underused NAT Gateway {res.name}", res.monthly_cost or 0,
                        f"${pricing.NAT_HOURLY}/h × 730 h (+ ${pricing.NAT_GB}/GB processed)",
                        {"gb_processed_per_day": gb}, "Consolidate traffic through a single NAT or use VPC endpoints.",
                        "medium", risk="Removing a per-AZ NAT reduces AZ fault isolation.")
            elif res.service == "elb":
                req = _avg(m.get("RequestCount"))
                if req is not None and req == 0:
                    add(res, "elb-idle", "medium", f"Load balancer {res.name} served no requests in {observed_days} days",
                        res.monthly_cost or 0, f"${pricing.ALB_HOURLY}/h × 730 h", {"requests_per_day": req},
                        "Delete the load balancer if no longer referenced.", "high")
            elif res.service == "lambda" and res.config.get("architecture") == "x86_64" and res.monthly_cost:
                saving = res.monthly_cost * (1 - pricing.LAMBDA_GB_SECOND_ARM / pricing.LAMBDA_GB_SECOND_X86)
                if saving >= 1:
                    add(res, "lambda-arm64", "low", f"Move Lambda {res.name} to arm64 (Graviton)", saving,
                        "GB-seconds × (x86 − arm64 price)", {"monthly_invocations": res.config["monthly_invocations"],
                                                             "avg_duration_ms": res.config["avg_duration_ms"]},
                        "Rebuild for arm64 and switch architecture after testing.", "medium",
                        proposal=self._iac_patch(ws, tf_by_addr.get(res.iac_address or ""), "architectures",
                                                 "x86_64", "arm64"),
                        risk="The deployment package must be built for arm64.")
            elif res.service == "s3" and not res.config.get("lifecycle_rules"):
                cold = res.config.get("objects_not_accessed_90d_ratio", 0)
                saving = res.config["size_gb"] * cold * (pricing.S3_STANDARD_GB - pricing.S3_IA_GB)
                if saving >= 5:
                    add(res, "s3-lifecycle", "low", f"Add lifecycle tiering to bucket {res.name}", saving,
                        f"{res.config['size_gb']} GB × {cold:.0%} cold × (Standard − Standard-IA)",
                        {"size_gb": res.config["size_gb"], "cold_ratio": cold},
                        "Add a lifecycle rule (Intelligent-Tiering or IA after 30–90 days).", "low",
                        savings_type="hypothetical")
        ctx.progress(0.75, "Utilisation analysis complete")

        cost = adapter.cost()
        totals: dict[str, Any] = {}
        if cost:
            for anomaly in detect_anomalies(cost.by_service):
                result.findings.append(FindingDraft(
                    rule_id="aws:cost-anomaly", category="anomaly", severity="medium",
                    title=f"Cost spike in {anomaly['service']} on {anomaly['date']} (z={anomaly['z_score']})",
                    description=f"Daily cost ${anomaly['cost']} vs trailing baseline ${anomaly['baseline']}.",
                    target=anomaly["service"], evidence={"scope": scope, **anomaly, "simulated": simulated,
                                                         "measured_spend": cost.measured},
                    recommendation="Investigate usage drivers for that day (deployments, traffic, misconfigured "
                                   "retries).", confidence="medium", data_source=source,  # type: ignore[arg-type]
                    fingerprint_key=f"aws|anomaly|{anomaly['service']}|{anomaly['date']}"))
            last30 = {svc: round(sum(v for _, v in pts[-30:]), 2) for svc, pts in cost.by_service.items()}
            totals = {"last_30_days": round(sum(last30.values()), 2), "by_service": last30,
                      "currency": cost.currency, "measured": cost.measured}
        else:
            result.notes.append("Cost data unavailable — no spend figures reported")
        savings = round(sum(f.estimated_monthly_savings or 0 for f in result.findings), 2)
        result.metrics = {"resources": len(inventory), "spend": totals, "estimated_monthly_savings": savings,
                          "simulated": simulated, "mode": adapter.report.mode, "data_source": adapter.report.meta,
                          "missing_evidence": adapter.report.missing_evidence[:20],
                          "errors": adapter.report.errors[:10]}
        if adapter.report.errors:
            result.status = "partial"
        result.artifacts.append(ArtifactDraft(kind="inventory", name="aws-inventory.json", media_type="application/json",
                                              content=json.dumps(
                                                  [r.__dict__ for r in inventory], default=str, indent=2)))
        ctx.progress(1.0, "AWS analysis complete")
        return result

    @staticmethod
    def _iac_patch(ws: Any, res: TfResource | None, key: str, old: str, new: str) -> ProposalDraft | None:
        if not res:
            return None
        line_no = res.attr_line(key, f'"{old}"')
        if line_no is None:
            return None
        text = ws.read_text(res.file)
        lines = text.splitlines(keepends=True)
        if f'"{old}"' not in lines[line_no - 1]:
            return None
        lines[line_no - 1] = lines[line_no - 1].replace(f'"{old}"', f'"{new}"', 1)
        diff = unified_diff(res.file, text, "".join(lines))
        if not diff:
            return None
        return ProposalDraft(kind="iac_change", title=f"Terraform: {res.address} {key} {old} → {new}",
                             summary="IaC change only — apply through your normal Terraform plan/apply pipeline. "
                                     "SkyForge never modifies live infrastructure.", diff=diff, files=[res.file])
