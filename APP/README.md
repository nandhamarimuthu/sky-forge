# SkyForge AI

Autonomous engineering platform: six specialised agents analyse a repository and its AWS project, propose
validated fixes, and present everything in one dashboard. Built to [skill.md](skill.md).

| Agent | What it really does | Tools it may use |
|---|---|---|
| 1 · Vulnerability Remediation | Parses `requirements*.txt`, `pyproject.toml`, `package.json`(+lock), `go.mod`, `pom.xml`, `build.gradle(.kts)`, `Gemfile.lock`, `composer.lock`, `Cargo.toml`, `*.csproj`; queries **OSV.dev**; proposes the minimal fixed version as a one-line diff; flags major bumps | repo.read, osv.query, manifest.patch |
| 2 · Unit Test & Coverage | **Python** (pytest + coverage), **JavaScript/TypeScript** (`npm test` baseline, drafted `node:test` suites — CJS, ESM and TS) and **Go** (`go test -cover`) run in the **Docker sandbox**. Untested side-effect-free functions get LLM-drafted tests (boundaries, branches, error paths); failing assertions are pruned, only passing tests are proposed; Python also gets sandbox-observed *characterization* tests | repo.read, static.radon, sandbox.execute, llm.generate |
| 3 · Functional Automation | Routes for FastAPI/Flask/Django, Express/Koa/Fastify/NestJS, Spring, Go (net/http, gin, echo, chi), Rails/Sinatra, Laravel, ASP.NET. Python apps run in-process: success, LLM-drafted happy-path payloads, auth, malformed/wrong-shape bodies, boundary & injection path params, reflected-XSS probes, stack-trace leaks, 404/405. Other stacks get a black-box `BASE_URL` suite | repo.read, sandbox.execute, llm.generate |
| 4 · AWS Cost Optimiser | Read-only inventory, metrics and cost → idle/oversized EC2 & RDS, unattached EBS, old snapshots, idle NAT/ELB, Lambda arm64, S3 tiering, z-score cost anomalies; Terraform patches when the resource is in the repo. **Skipped when the repo has no AWS Terraform** (and no export is selected) | repo.read, terraform.parse, aws.read |
| 5 · Code Health | Python: Radon complexity/MI + Ruff lint and safe-fix diffs. **~20 other languages** (JS/TS, Java, Kotlin, Go, C#, C/C++, Ruby, PHP, Swift, Rust, Scala…) via lizard complexity. Duplication and git-churn hotspots across all | repo.read, static.ruff, static.radon |
| 6 · Security Guardrails | Secret scanning, dangerous code patterns for Python, JS/TS, Java/Kotlin, Go, Ruby, PHP, C#, Rust; Dockerfile/CI/Terraform policies — **and** a deterministic policy engine that validates every proposed change | repo.read, terraform.parse |

**What is real:** repository cloning, OSV lookups, Ruff/Radon, Docker test execution, LLM test drafting and
explanations (Ollama `gemma3` via CrewAI), patch validation and remediation.

**AWS cost data (default: simulated from Terraform).** Each scan reads the AWS resources declared in the repo's
Terraform (`aws_instance`, `aws_db_instance`, `aws_ebs_volume`, `aws_nat_gateway`, `aws_lb`, `aws_lambda_function`,
`aws_s3_bucket`, …) and simulates one month of Cost & Usage Report rows, inventory and CloudWatch utilisation for them
(deterministic per project, labelled **simulated**). No AWS Terraform → the AWS agent is skipped. For measured numbers,
pick a bundled export in `fixtures/aws/` or upload your own (`scripts/export_aws_dump.sh`, zipped) on the AWS page.
The same reader handles real exports: a CUR CSV (`lineItem/*` columns), AWS CLI `describe-*` JSON and CloudWatch daily
metrics. `AWS_MODE=live` (read-only boto3) is also available. The database starts empty; every project, scan,
finding and test run is produced by a real scan.

**Speed:** agents run in parallel; sandbox dependency installs (pip, npm, Go modules) are cached by lockfile hash;
LLM drafting runs concurrently; LLM explanations are filled in *after* the scan completes, so results appear as soon
as the agents finish.

| Dump file | Source command |
|---|---|
| `manifest.json` | account, region, period, project tag |
| `cost_and_usage.csv` | CUR (or converted `ce get-cost-and-usage --granularity DAILY`) |
| `ec2_instances.json`, `ebs_volumes.json`, `ebs_snapshots.json`, `rds_instances.json`, `nat_gateways.json`, `load_balancers.json`, `lambda_functions.json`, `s3_buckets.json` | `aws ec2/rds/elbv2/lambda/s3api describe-*/list-*` |
| `cloudwatch_metrics.json` | `aws cloudwatch get-metric-statistics --period 86400` (CPU, connections, bytes, requests…) |

## Quick start

Prerequisites: Python 3.11, Node 20+, git, Docker (for test execution), optionally Ollama.

```bash
cp .env.example .env                       # then replace the placeholder tokens
python3.11 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cd frontend && npm install && npm run build && cd ..
cd backend && ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 and sign in with a token from `API_TOKENS`. The database migrates automatically on
start-up (Alembic). For frontend development run `npm run dev` in `frontend/` (http://localhost:5173, proxies `/api`).

LLM: `ollama pull gemma3 && ollama serve`, plus `pip install -e ".[llm]"` for CrewAI. `/api/v1/health` reports
`llm.reachable`/`model_available`/`crewai_installed`. Without them, explanations fall back to deterministic
templates and tests to the sandbox-observed characterization strategy.

### Sample repositories (bundled, realistic)

| Repo | Stack | Planted issues |
|---|---|---|
| `fixture:demo-shop` | Flask shop + Express storefront, Terraform, Dockerfile, GitHub Actions | vulnerable pins (requests, urllib3, flask, lodash, axios, express), hard-coded AWS key, `yaml.load`, `verify=False`, `shell=True`, `innerHTML`, open SG, public S3/RDS, CI script injection, complex untested functions |
| `fixture:orders-api` | FastAPI orders service, Terraform (EC2 + 2×RDS), Dockerfile, GitHub Actions | vulnerable pins (fastapi 0.95, starlette, python-multipart, jinja2, cryptography, PyJWT…), hard-coded secrets, SQL f-string injection, pickle/yaml, broken refund authorisation, divide-by-zero report endpoint, `pull_request_target` workflow, oversized/unencrypted/public RDS |

Each has a matching AWS dump (Name tags such as `demo-shop-api` / RDS identifiers link usage to the Terraform
resources, so rightsizing findings come with an IaC patch). Regenerate dumps with
`.venv/bin/python scripts/build_sample_aws_dumps.py`.

### Demo workflow (no AWS credentials needed)

1. **Add services** → pick a sample (`fixture:demo-shop`, `fixture:orders-api`) or any public GitHub repo, e.g.
   `https://github.com/we45/Vulnerable-Flask-App`, and choose the AWS cost data dump.
2. Open the project → **Run scan**. Watch live progress and agent logs (Server-Sent Events).
3. Open a finding → evidence, explanation, the proposed diff and guardrail checks → **Approve fix** →
   **Apply to isolated branch & verify**.
   The patch is committed to an isolated local branch (`skyforge/fix-…`) in a git worktree and re-verified
   (OSV re-query, sandbox test run, Ruff re-check, Terraform syntax, or secret re-scan).
4. Explore Security, Testing, AWS Optimization, Code Health, Agent Center and Settings & Audit.

### Pushing fixes and opening pull requests (GitHub)

Preferred: create and install a GitHub App, grant **Contents: read/write** and **Pull requests: read/write**, then put
its App ID, installation ID and downloaded private-key file path in `APP/.env`:

```dotenv
GITHUB_APP_ID=123456
GITHUB_APP_INSTALLATION_ID=12345678
GITHUB_APP_PRIVATE_KEY_PATH=/absolute/path/outside/the/repository/app.private-key.pem
```

Restart SkyForge. It signs a short-lived App JWT locally, exchanges it for a short-lived installation token, caches
that token until shortly before expiry, then uses it to push and open the draft PR. The PEM is read from disk and
never stored in the database, logged, or sent to the browser. Keep the PEM out of git and restrict its filesystem
permissions. Install the App on each target repository. A per-project `token_secret_ref` PAT or `GITHUB_TOKEN`
remains a fallback. Click **Push branch & open PR** on an approved, verified fix:

| Repository | What happens |
|---|---|
| You have push access | `skyforge/fix-…` branch pushed, draft PR against the scanned branch |
| Public repo you don't own | forked to your account, draft PR inside the fork (upstream is never contacted) |
| Bundled sample (`fixture:`) | With a PAT, a private `skyforge-<name>` repo is created. With an App, pre-create the remote repo and install the App on it; then register that remote as a project. |

The installation token is only passed to git through environment config (never in arguments, logs or the DB); every
push is audited. `POST /api/v1/findings/{id}/pull-request {"proposal_id": …}` is idempotent. Fork creation may
require the App's **Administration** permission, depending on repository ownership and organization policy.

## Architecture

```
frontend/ (React + TS + Vite, MUI, Recharts, TanStack Query, React Router)
   │  Bearer token · REST + SSE (fetch-stream)
backend/app/
   api/            FastAPI routes, auth/role/project dependencies, rate limiting, structured errors
   orchestration/  ScanOrchestrator (validate → clone → dispatch agents → schema-validate → dedupe →
                   guardrails → persist → explain), CrewAI/Ollama explanation crew
   agents/         six agents, explicit tool allow-lists enforced by AgentContext.tool()
   adapters/       repository (safe git clone), scanners (OSV, manifests, Ruff/Radon, Terraform),
                   aws (dump / live read-only), sandbox (Docker)
   services/       remediation workflow, audit, LLM client, read models
   workers/        background scan worker; durable state in the DB, restart reconciliation
   models/ db/     SQLAlchemy models; Alembic migrations in backend/migrations
```

Scan lifecycle: `queued → running → completed | partial | failed | cancelled`; each agent run has its own state
(`queued, running, completed, failed, timed_out, cancelled, skipped`). One failing agent marks the scan `partial`,
never `completed`. Proposal lifecycle: `validated | rejected_by_policy → approved → applying → applied →
verified | verification_failed`.

## Security model

- Bearer tokens (SHA-256 digests in memory, constant-time compare); roles `viewer`, `engineer`, `admin`;
  optional per-token project scope. Placeholder tokens are refused when `APP_ENV=prod`.
- Every denial and every approval/apply/verify is written to the audit log; secrets are redacted from logs,
  events, artifacts and stored diffs (secret fixes are rebuilt from a codemod recipe at apply time).
- Repo URLs restricted to allow-listed hosts over https; clones run with hooks, submodules, symlinks and the user's
  git config disabled; size-limited; all file access is traversal-safe.
- Repository code is only executed in Docker with `--cap-drop ALL`, `no-new-privileges`, read-only root, CPU/memory/PID
  limits and `--network none` for test execution. No Docker → execution is refused (fail closed).
- Guardrail policy (deterministic, fail-closed): allowed paths per change type, protected files (CI, `.env`, keys),
  declared-vs-actual files, size limits, dangerous content, secrets, prompt-injection text, version-only dependency
  edits, `git apply --check`, post-apply syntax checks. Re-run at approval and again at apply time.
- Merges and infrastructure changes are never performed. Pushing a fix branch and opening a **draft** PR happens only
  when a human clicks *Push branch & open PR* on an approved + verified fix (never force-push, never the default branch).
- AWS access is read-only by construction (only Describe/Get/List calls), with region and service allow-lists.

## API

All under `/api/v1` (OpenAPI at `/api/docs`): `health`, `dashboard/summary`, `projects` (CRUD),
`projects/{id}/scans`, `scans/{id}`, `scans/{id}/events` (SSE, `?stream=false` for JSON), `scans/{id}/cancel`,
`scans/{id}/artifacts/{artifact_id}`, `findings` (filter/sort/paginate/facets), `findings/{id}`,
`findings/{id}/review`, `findings/{id}/remediate`, `findings/{id}/pull-request`, `agents`, `agents/{id}/runs`, `projects/{id}/aws/resources`,
`projects/{id}/aws/cost`, `projects/{id}/aws/source` (PUT, pick a bundled dump), `projects/{id}/aws/dump`
(POST zip upload), `aws/dumps`, `projects/{id}/quality`, `test-runs`, `settings`, `audit`.

## Quality checks

```bash
.venv/bin/python -m pytest          # unit + API integration tests (no network, no Docker needed)
.venv/bin/ruff check backend/app
.venv/bin/mypy
cd frontend && npm run build        # tsc + vite
```

## Limitations

- Test execution covers Python, JavaScript/TypeScript and Go. Other languages get complexity, security rules,
  dependency checks and black-box HTTP suites, but no unit-test execution yet.
- Spend comes from the dump's CUR lines; savings combine that spend with static on-demand list prices and are
  labelled estimates. The bundled dumps are realistic samples, not a real account — upload your own export for real
  numbers.
- Local LLMs are slow: a full scan with gemma3 takes a few minutes (explanations + drafted tests).
- Rate limiting and the worker pool are in-process (single instance). Use PostgreSQL via `DATABASE_URL` for deployment.
- Pull requests are GitHub-only (GitLab/Bitbucket: download the patch artifact).

## Troubleshooting

- *"Docker sandbox unavailable"* — start Docker Desktop; the first sandboxed run pulls `python:3.11-slim`.
- *LLM offline* — `ollama serve` and `ollama pull gemma3`, or set another model in Settings.
- *Repository rejected* — only https URLs on `ALLOWED_GIT_HOSTS` (or `fixture:<name>`) are accepted.
- *Proposal "stale" on approve* — the workspace changed since the scan; re-scan the project.
