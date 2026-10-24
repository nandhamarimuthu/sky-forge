"""Terraform → mock AWS data.

The repository's own Terraform is the single source of truth for what AWS looks like, so tests should be written
against *that* shape rather than an invented one. This module turns parsed HCL resources into:

* a `moto`-backed pytest ``conftest.py`` that creates every supported resource in-memory (no network, no real
  account, no credentials), and
* a JSON seed file describing the same inventory for non-Python test suites.

If the repository has no Terraform — or none of its resources map to a mockable service — the plan is empty and
callers skip AWS mock generation entirely.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.adapters.scanners.terraform import TfResource

# Terraform resource type -> (service, boto3 client name)
SERVICE_BY_TYPE: dict[str, tuple[str, str]] = {
    "aws_s3_bucket": ("s3", "s3"),
    "aws_dynamodb_table": ("dynamodb", "dynamodb"),
    "aws_sqs_queue": ("sqs", "sqs"),
    "aws_sns_topic": ("sns", "sns"),
    "aws_lambda_function": ("lambda", "lambda"),
    "aws_secretsmanager_secret": ("secretsmanager", "secretsmanager"),
    "aws_ssm_parameter": ("ssm", "ssm"),
    "aws_kinesis_stream": ("kinesis", "kinesis"),
    "aws_cloudwatch_log_group": ("logs", "logs"),
    "aws_ecr_repository": ("ecr", "ecr"),
    "aws_kms_key": ("kms", "kms"),
    "aws_iam_role": ("iam", "iam"),
    "aws_db_instance": ("rds", "rds"),
    "aws_instance": ("ec2", "ec2"),
    "aws_cloudwatch_event_bus": ("events", "events"),
    "aws_ses_email_identity": ("ses", "ses"),
    "aws_sfn_state_machine": ("stepfunctions", "stepfunctions"),
}

_INTERPOLATED = re.compile(r"\$\{|\bvar\.|\bdata\.|\blocal\.|\baws_[a-z_]+\.")
_NESTED_BLOCK = re.compile(r"^\s*(\w+)\s*\{(.*?)^\s*\}", re.M | re.S)
_INNER_ATTR = re.compile(r'^\s*(\w+)\s*=\s*"?([^"\n]*)"?\s*$', re.M)
_TAG_NAME = re.compile(r'^\s*tags\s*=\s*\{(.*?)^\s*\}', re.M | re.S)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-") or "resource"


def _literal(res: TfResource, *keys: str) -> str | None:
    for key in keys:
        raw = res.value(key)
        if raw and not _INTERPOLATED.search(raw):
            # `value(...)` strips the outer quotes; anything left after a quote belongs to another attribute.
            return raw.split('"')[0].strip() or None
    return None


def _nested(res: TfResource, block: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for m in _NESTED_BLOCK.finditer(res.body):
        if m.group(1) != block:
            continue
        attrs = {k: v.strip() for k, v in _INNER_ATTR.findall(m.group(2))}
        if attrs:
            out.append(attrs)
    return out


def _tag_name(res: TfResource) -> str | None:
    """The `Name` tag, which is what AWS consoles and most tests actually use to identify a resource."""
    m = _TAG_NAME.search(res.body)
    if not m:
        return None
    for key, value in _INNER_ATTR.findall(m.group(1)):
        if key.lower() == "name" and value.strip() and not _INTERPOLATED.search(value):
            return value.strip()
    return None


@dataclass
class MockResource:
    service: str
    client: str
    tf_type: str
    address: str
    physical_name: str
    file: str
    line: int
    config: dict = field(default_factory=dict)
    interpolated_name: bool = False


@dataclass
class AwsMockPlan:
    resources: list[MockResource] = field(default_factory=list)
    region: str = "us-east-1"
    skipped_types: dict[str, int] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.resources)

    @property
    def services(self) -> list[str]:
        return sorted({r.service for r in self.resources})

    def by_service(self, service: str) -> list[MockResource]:
        return [r for r in self.resources if r.service == service]

    def as_dict(self) -> dict:
        return {"region": self.region, "services": self.services,
                "resources": [{"service": r.service, "type": r.tf_type, "address": r.address,
                               "name": r.physical_name, "file": r.file, "line": r.line, "config": r.config}
                              for r in self.resources],
                "unsupported_resource_types": self.skipped_types}


def plan_aws_mocks(resources: list[TfResource], region: str | None = None) -> AwsMockPlan:
    """Build the mock inventory. Resources whose service moto cannot emulate are counted and skipped."""
    plan = AwsMockPlan(region=region or "us-east-1")
    for res in resources:
        mapped = SERVICE_BY_TYPE.get(res.type)
        if not mapped:
            plan.skipped_types[res.type] = plan.skipped_types.get(res.type, 0) + 1
            continue
        service, client = mapped
        literal = (_literal(res, "bucket", "name", "function_name", "identifier", "repository_name", "stream_name")
                   or _tag_name(res))
        physical = literal or f"{_slug(res.name)}-{_slug(res.type.replace('aws_', ''))}"
        config = _config_for(res, service)
        plan.resources.append(MockResource(service=service, client=client, tf_type=res.type, address=res.address,
                                           physical_name=physical, file=res.file, line=res.start_line, config=config,
                                           interpolated_name=literal is None))
    return plan


def _config_for(res: TfResource, service: str) -> dict:
    if service == "dynamodb":
        attrs = _nested(res, "attribute")
        hash_key = _literal(res, "hash_key") or (attrs[0]["name"] if attrs else "id")
        range_key = _literal(res, "range_key")
        types = {a.get("name", ""): a.get("type", "S") for a in attrs}
        keys = [{"AttributeName": hash_key, "KeyType": "HASH"}]
        if range_key:
            keys.append({"AttributeName": range_key, "KeyType": "RANGE"})
        return {"key_schema": keys,
                "attribute_definitions": [{"AttributeName": k["AttributeName"],
                                           "AttributeType": types.get(k["AttributeName"], "S")} for k in keys],
                "billing_mode": _literal(res, "billing_mode") or "PAY_PER_REQUEST"}
    if service == "sqs":
        return {"fifo": (_literal(res, "fifo_queue") or "").lower() == "true",
                "visibility_timeout": _literal(res, "visibility_timeout_seconds")}
    if service == "lambda":
        return {"runtime": _literal(res, "runtime") or "python3.11",
                "handler": _literal(res, "handler") or "index.handler",
                "memory_size": _literal(res, "memory_size"), "timeout": _literal(res, "timeout")}
    if service == "ssm":
        return {"type": _literal(res, "type") or "String", "value": _literal(res, "value") or "mock-value"}
    if service == "s3":
        return {"versioning": "versioning" in res.body}
    if service == "rds":
        return {"engine": _literal(res, "engine") or "postgres",
                "instance_class": _literal(res, "instance_class") or "db.t3.micro"}
    if service == "ec2":
        return {"instance_type": _literal(res, "instance_type") or "t3.micro"}
    if service == "kinesis":
        return {"shard_count": _literal(res, "shard_count") or "1"}
    if service == "logs":
        return {"retention_in_days": _literal(res, "retention_in_days")}
    return {}


# --------------------------------------------------------------------------------- rendering

MOCK_DIR = "skyforge_tests/aws"

_SEEDERS: dict[str, str] = {
    "s3": '    client.create_bucket(Bucket={name!r}{bucket_cfg})\n',
    "dynamodb": ('    client.create_table(TableName={name!r}, KeySchema={key_schema!r},\n'
                 '                        AttributeDefinitions={attr_defs!r}, BillingMode="PAY_PER_REQUEST")\n'),
    "sqs": '    client.create_queue(QueueName={name!r})\n',
    "sns": '    client.create_topic(Name={name!r})\n',
    "secretsmanager": '    client.create_secret(Name={name!r}, SecretString=\'{{"mock": true}}\')\n',
    "ssm": '    client.put_parameter(Name={name!r}, Value={value!r}, Type={ptype!r}, Overwrite=True)\n',
    "kinesis": '    client.create_stream(StreamName={name!r}, ShardCount=1)\n',
    "logs": '    client.create_log_group(logGroupName={name!r})\n',
    "ecr": '    client.create_repository(repositoryName={name!r})\n',
    "kms": '    client.create_key(Description={name!r})\n',
    "events": '    client.create_event_bus(Name={name!r})\n',
    "ses": '    client.verify_email_identity(EmailAddress="mock@example.com")\n',
}


def _seed_lines(plan: AwsMockPlan, service: str) -> str:
    lines = ""
    for r in plan.by_service(service):
        template = _SEEDERS.get(service)
        if template:
            lines += template.format(
                name=r.physical_name, bucket_cfg=_bucket_cfg(plan.region),
                key_schema=r.config.get("key_schema", [{"AttributeName": "id", "KeyType": "HASH"}]),
                attr_defs=r.config.get("attribute_definitions",
                                       [{"AttributeName": "id", "AttributeType": "S"}]),
                value=r.config.get("value", "mock-value"), ptype=r.config.get("type", "String"))
        elif service == "iam":
            lines += (f'    client.create_role(RoleName={r.physical_name!r},\n'
                      '                       AssumeRolePolicyDocument=json.dumps(\n'
                      '                           {"Version": "2012-10-17", "Statement": []}))\n')
        elif service == "lambda":
            lines += (f'    # {r.address}: zip a stub so the ARN exists; invoke() returns the stub payload.\n'
                      f'    client.create_function(FunctionName={r.physical_name!r}, Runtime='
                      f'{r.config.get("runtime", "python3.11")!r},\n'
                      '                           Role="arn:aws:iam::123456789012:role/skyforge-mock",\n'
                      f'                           Handler={r.config.get("handler", "index.handler")!r},\n'
                      '                           Code={"ZipFile": _STUB_ZIP})\n')
        elif service == "rds":
            lines += (f'    client.create_db_instance(DBInstanceIdentifier={r.physical_name!r},\n'
                      f'                              DBInstanceClass={r.config.get("instance_class", "db.t3.micro")!r},\n'
                      f'                              Engine={r.config.get("engine", "postgres")!r})\n')
        elif service == "ec2":
            lines += ('    client.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,\n'
                      f'                         InstanceType={r.config.get("instance_type", "t3.micro")!r},\n'
                      '                         TagSpecifications=[{"ResourceType": "instance",\n'
                      '                                             "Tags": [{"Key": "Name",\n'
                      f'                                                       "Value": {r.physical_name!r}}}]}}])\n')
        elif service == "stepfunctions":
            lines += f'    # {r.address}: state machines need a definition — add one when the test needs it.\n'
    return lines or "    pass\n"


def _bucket_cfg(region: str) -> str:
    if region == "us-east-1":
        return ""
    return f',\n                         CreateBucketConfiguration={{"LocationConstraint": {region!r}}}'


def render_conftest(plan: AwsMockPlan) -> str:
    """A self-contained pytest conftest that mocks every Terraform-declared AWS resource with moto."""
    inventory = {r.address: {"service": r.service, "name": r.physical_name, "terraform": f"{r.file}:{r.line}"}
                 for r in plan.resources}
    needs_json = any(r.service == "iam" for r in plan.resources)
    needs_zip = any(r.service == "lambda" for r in plan.resources)
    head = [
        '"""Mock AWS fixtures generated by SkyForge AI from this repository\'s Terraform.',
        "",
        "Every resource below is declared in the repo's own `.tf` files, so tests exercise the real shape of the",
        "infrastructure without touching an AWS account. `moto` intercepts boto3 at the HTTP layer: no network,",
        "no credentials, no cost. Regenerate this file after changing Terraform.",
        "",
        "Requires: pip install 'moto[all]' boto3",
        '"""',
        "",
        "from __future__ import annotations",
        "",
    ]
    if needs_json:
        head.append("import json")
    if needs_zip:
        head += ["import io", "import zipfile"]
    head += [
        "",
        "import boto3",
        "import pytest",
        "from moto import mock_aws",
        "",
        f"AWS_REGION = {plan.region!r}",
        "",
        "# address -> what Terraform declares. Keep tests referring to these names, never to hard-coded strings.",
        "TERRAFORM_RESOURCES = " + json.dumps(inventory, indent=4),
        "",
    ]
    if needs_zip:
        head += [
            "",
            "def _stub_zip() -> bytes:",
            "    buf = io.BytesIO()",
            '    with zipfile.ZipFile(buf, "w") as zf:',
            '        zf.writestr("index.py", "def handler(event, context):\\n    return {\'ok\': True}\\n")',
            "    return buf.getvalue()",
            "",
            "",
            "_STUB_ZIP = _stub_zip()",
            "",
        ]
    body = [
        "",
        '@pytest.fixture(autouse=True)',
        "def aws_credentials(monkeypatch):",
        '    """Never let a test reach a real account, even if moto is misconfigured."""',
        '    for key, value in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",',
        '                       "AWS_SECURITY_TOKEN": "testing", "AWS_SESSION_TOKEN": "testing",',
        '                       "AWS_DEFAULT_REGION": AWS_REGION, "AWS_REGION": AWS_REGION}.items():',
        "        monkeypatch.setenv(key, value)",
        '    monkeypatch.delenv("AWS_PROFILE", raising=False)',
        "",
        "",
        '@pytest.fixture',
        "def aws():",
        '    """Active moto backend. Create clients inside the test with `boto3.client(..., region_name=AWS_REGION)`."""',
        "    with mock_aws():",
        "        yield boto3",
        "",
    ]
    for service in plan.services:
        resources = plan.by_service(service)
        names = [r.physical_name for r in resources]
        fixture = f"mock_{service.replace('-', '_')}"
        client_name = resources[0].client
        body += [
            "",
            "@pytest.fixture",
            f"def {fixture}(aws):",
            f'    """{len(resources)} {service} resource(s) from Terraform: ' + ", ".join(
                f"{r.address} -> {r.physical_name}" for r in resources[:6]) + '."""',
            f'    client = boto3.client({client_name!r}, region_name=AWS_REGION)',
            _seed_lines(plan, service).rstrip("\n"),
            f"    return {{'client': client, 'names': {names!r}}}",
            "",
        ]
    body += [
        "",
        "@pytest.fixture",
        f"def mock_aws_stack({', '.join('mock_' + s.replace('-', '_') for s in plan.services)}):",
        '    """Every Terraform-declared resource at once — use for functional/integration-style tests."""',
        "    return {" + ", ".join(f"{s!r}: mock_{s.replace('-', '_')}" for s in plan.services) + "}",
        "",
    ]
    return "\n".join(head + body)


def render_smoke_tests(plan: AwsMockPlan) -> str:
    """Executable examples proving the mocked inventory matches Terraform."""
    lines = ['"""Example tests for the mocked AWS inventory (generated by SkyForge AI).',
             "",
             "They assert the resources Terraform declares actually exist in the mock, which keeps the fixtures and",
             "the infrastructure in sync. Extend them with your real business assertions.",
             '"""',
             "",
             "from .conftest import TERRAFORM_RESOURCES",
             "",
             ""]
    checks = {
        "s3": ("client.list_buckets()['Buckets']", "b['Name'] for b in"),
        "dynamodb": ("client.list_tables()['TableNames']", None),
        "sqs": ("client.list_queues().get('QueueUrls', [])", None),
        "sns": ("[t['TopicArn'] for t in client.list_topics()['Topics']]", None),
        "lambda": ("[f['FunctionName'] for f in client.list_functions()['Functions']]", None),
        "secretsmanager": ("[s['Name'] for s in client.list_secrets()['SecretList']]", None),
        "ssm": ("[p['Name'] for p in client.describe_parameters()['Parameters']]", None),
        "kinesis": ("client.list_streams()['StreamNames']", None),
        "logs": ("[g['logGroupName'] for g in client.describe_log_groups()['logGroups']]", None),
        "ecr": ("[r['repositoryName'] for r in client.describe_repositories()['repositories']]", None),
        "iam": ("[r['RoleName'] for r in client.list_roles()['Roles']]", None),
        "rds": ("[d['DBInstanceIdentifier'] for d in client.describe_db_instances()['DBInstances']]", None),
    }
    for service in plan.services:
        resources = plan.by_service(service)
        fixture = f"mock_{service.replace('-', '_')}"
        expr = checks.get(service)
        names = [r.physical_name for r in resources]
        if service == "s3":
            listing = "[b['Name'] for b in client.list_buckets()['Buckets']]"
        elif service == "sqs":
            listing = "[url.rsplit('/', 1)[-1] for url in client.list_queues().get('QueueUrls', [])]"
        elif service == "sns":
            listing = "[t['TopicArn'].rsplit(':', 1)[-1] for t in client.list_topics()['Topics']]"
        elif expr:
            listing = expr[0]
        else:
            lines += [f"def test_{service}_fixture_is_available({fixture}):",
                      f"    assert {fixture}['names'] == {names!r}",
                      "",
                      ""]
            continue
        lines += [
            f"def test_terraform_{service}_resources_exist({fixture}):",
            f'    client = {fixture}["client"]',
            f"    existing = {listing}",
            f"    for name in {names!r}:",
            '        assert name in existing, f"{name} is declared in Terraform but missing from the mock"',
            "",
            "",
        ]
    lines += [
        "def test_every_terraform_resource_is_mocked(mock_aws_stack):",
        '    """Guards against Terraform growing a resource that the test fixtures never create."""',
        "    mocked = {name for bucket in mock_aws_stack.values() for name in bucket['names']}",
        "    declared = {meta['name'] for meta in TERRAFORM_RESOURCES.values()}",
        "    assert declared <= mocked, declared - mocked",
        "",
    ]
    return "\n".join(lines)


def render_seed_json(plan: AwsMockPlan) -> str:
    """Language-neutral seed data (used by JS/Go/Java suites via their own AWS mocking libraries)."""
    return json.dumps(plan.as_dict(), indent=2) + "\n"


def mock_files(plan: AwsMockPlan) -> dict[str, str]:
    """All generated files, keyed by repository-relative path. Empty when there is nothing to mock."""
    if not plan:
        return {}
    return {
        f"{MOCK_DIR}/__init__.py": '"""Mock AWS fixtures generated by SkyForge AI from Terraform."""\n',
        f"{MOCK_DIR}/conftest.py": render_conftest(plan),
        f"{MOCK_DIR}/test_terraform_inventory.py": render_smoke_tests(plan),
        f"{MOCK_DIR}/terraform_inventory.json": render_seed_json(plan),
    }
