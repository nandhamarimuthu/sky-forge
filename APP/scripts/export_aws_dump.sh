#!/usr/bin/env bash
# Export one month of AWS data in the format SkyForge's dump adapter reads. Read-only calls only.
#
#   AWS_PROFILE=prod AWS_REGION=eu-west-2 PROJECT_TAG=orders-api ./scripts/export_aws_dump.sh ./my-dump
#   (optional) CUR_CSV=/path/to/cost-and-usage-report.csv to use your Cost & Usage Report instead of Cost Explorer
#
# Then zip the folder and upload it on the AWS Optimization page (or copy it to fixtures/aws/<name>).
set -euo pipefail

OUT="${1:?usage: export_aws_dump.sh <output-dir>}"
REGION="${AWS_REGION:?set AWS_REGION}"
TAG="${PROJECT_TAG:-}"
DAYS="${DAYS:-30}"
mkdir -p "$OUT"

END=$(python3 -c "import datetime;print(datetime.date.today().isoformat())")
START=$(python3 -c "import datetime;print((datetime.date.today()-datetime.timedelta(days=$DAYS)).isoformat())")
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
FILTER=()
[[ -n "$TAG" ]] && FILTER=(--filters "Name=tag:Project,Values=$TAG")

echo "Exporting account $ACCOUNT ($REGION) $START → $END ${TAG:+(Project=$TAG)}"
aws ec2 describe-instances --region "$REGION" "${FILTER[@]}" > "$OUT/ec2_instances.json"
aws ec2 describe-volumes --region "$REGION" "${FILTER[@]}" > "$OUT/ebs_volumes.json"
aws ec2 describe-snapshots --region "$REGION" --owner-ids self "${FILTER[@]}" > "$OUT/ebs_snapshots.json"
aws ec2 describe-nat-gateways --region "$REGION" > "$OUT/nat_gateways.json"
aws rds describe-db-instances --region "$REGION" > "$OUT/rds_instances.json"
aws elbv2 describe-load-balancers --region "$REGION" > "$OUT/load_balancers.json"
aws lambda list-functions --region "$REGION" > "$OUT/lambda_functions.json"

python3 - "$OUT" "$REGION" <<'PY'
import json, subprocess, sys
out, region = sys.argv[1], sys.argv[2]
buckets = json.loads(subprocess.run(["aws", "s3api", "list-buckets"], capture_output=True, text=True, check=True).stdout)
for b in buckets.get("Buckets", []):
    r = subprocess.run(["aws", "s3api", "get-bucket-lifecycle-configuration", "--bucket", b["Name"]],
                       capture_output=True, text=True)
    b["LifecycleRules"] = json.loads(r.stdout).get("Rules") if r.returncode == 0 else None
json.dump(buckets, open(f"{out}/s3_buckets.json", "w"), indent=1)
PY

python3 - "$OUT" "$REGION" "$START" "$END" <<'PY'
import json, subprocess, sys
out, region, start, end = sys.argv[1:5]
load = lambda f: json.load(open(f"{out}/{f}"))
targets = []
for r in load("ec2_instances.json").get("Reservations", []):
    for i in r["Instances"]:
        iid = i["InstanceId"]
        targets += [("AWS/EC2", "CPUUtilization", [("InstanceId", iid)], "Average"),
                    ("AWS/EC2", "NetworkIn", [("InstanceId", iid)], "Sum")]
for db in load("rds_instances.json").get("DBInstances", []):
    d = db["DBInstanceIdentifier"]
    targets += [("AWS/RDS", "CPUUtilization", [("DBInstanceIdentifier", d)], "Average"),
                ("AWS/RDS", "DatabaseConnections", [("DBInstanceIdentifier", d)], "Average")]
for n in load("nat_gateways.json").get("NatGateways", []):
    targets.append(("AWS/NATGateway", "BytesOutToDestination", [("NatGatewayId", n["NatGatewayId"])], "Sum"))
for lb in load("load_balancers.json").get("LoadBalancers", []):
    key = lb["LoadBalancerArn"].split("loadbalancer/", 1)[-1]
    targets.append(("AWS/ApplicationELB", "RequestCount", [("LoadBalancer", key)], "Sum"))
for f in load("lambda_functions.json").get("Functions", []):
    targets += [("AWS/Lambda", "Invocations", [("FunctionName", f["FunctionName"])], "Sum"),
                ("AWS/Lambda", "Duration", [("FunctionName", f["FunctionName"])], "Average")]
for b in load("s3_buckets.json").get("Buckets", []):
    targets.append(("AWS/S3", "BucketSizeBytes", [("BucketName", b["Name"]), ("StorageType", "StandardStorage")],
                    "Average"))
metrics = []
for ns, name, dims, stat in targets:
    args = ["aws", "cloudwatch", "get-metric-statistics", "--region", region, "--namespace", ns, "--metric-name", name,
            "--start-time", start, "--end-time", end, "--period", "86400", "--statistics", stat, "Maximum",
            "--dimensions", *[f"Name={k},Value={v}" for k, v in dims]]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode == 0:
        data = json.loads(r.stdout)
        metrics.append({"Namespace": ns, "MetricName": name, "Statistic": stat,
                        "Dimensions": [{"Name": k, "Value": v} for k, v in dims], **data})
json.dump(metrics, open(f"{out}/cloudwatch_metrics.json", "w"), indent=1)
PY

if [[ -n "${CUR_CSV:-}" ]]; then
  cp "$CUR_CSV" "$OUT/cost_and_usage.csv"
else
  aws ce get-cost-and-usage --time-period "Start=$START,End=$END" --granularity DAILY --metrics UnblendedCost \
    --group-by Type=DIMENSION,Key=SERVICE > "$OUT/ce_daily.json"
  python3 - "$OUT" "$TAG" <<'PY'
import csv, json, sys
out, tag = sys.argv[1], sys.argv[2]
codes = {"Amazon Elastic Compute Cloud - Compute": "AmazonEC2", "EC2 - Other": "AmazonEC2",
         "Amazon Relational Database Service": "AmazonRDS", "Amazon Simple Storage Service": "AmazonS3",
         "AWS Lambda": "AWSLambda", "Amazon Elastic Load Balancing": "AWSELB", "AmazonCloudWatch": "AmazonCloudWatch"}
cols = ["lineItem/UsageStartDate", "lineItem/ProductCode", "lineItem/ResourceId", "lineItem/UnblendedCost",
        "product/ProductName", "resourceTags/user:Project"]
with open(f"{out}/cost_and_usage.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=cols)
    w.writeheader()
    for day in json.load(open(f"{out}/ce_daily.json"))["ResultsByTime"]:
        for g in day["Groups"]:
            w.writerow({"lineItem/UsageStartDate": day["TimePeriod"]["Start"] + "T00:00:00Z",
                        "lineItem/ProductCode": codes.get(g["Keys"][0], g["Keys"][0]), "lineItem/ResourceId": "",
                        "lineItem/UnblendedCost": g["Metrics"]["UnblendedCost"]["Amount"],
                        "product/ProductName": g["Keys"][0], "resourceTags/user:Project": tag})
PY
  echo "Note: Cost Explorer has no per-resource costs; provide CUR_CSV for resource-level savings."
fi

python3 - "$OUT" "$ACCOUNT" "$REGION" "$START" "$END" "$TAG" <<'PY'
import datetime, json, sys
out, acct, region, start, end, tag = sys.argv[1:7]
json.dump({"account_id": acct, "region": region, "currency": "USD", "period_start": start, "period_end": end,
           "exported_at": datetime.datetime.utcnow().isoformat() + "Z", "project_tag": tag,
           "format": "skyforge-aws-dump/v1", "description": f"Export of {acct} ({region})"},
          open(f"{out}/manifest.json", "w"), indent=2)
PY
echo "Done → $OUT"
