# SkyForge AI

Autonomous engineering platform: six specialised agents analyse a repository and its AWS project, propose
validated fixes, and present everything in one dashboard. Built to [skill.md](skill.md).

| Agent | What it really does | Tools it may use |
|---|---|---|
| 1 · Vulnerability Remediation | Parses `requirements*.txt`, `pyproject.toml`, `package.json`(+lock), `go.mod`; queries **OSV.dev**; proposes the minimal fixed version as a one-line diff; flags major bumps | repo.read, osv.query, manifest.patch |
| 2 · Unit Test & Coverage | Measures Python and JavaScript/TypeScript coverage in the **Docker sandbox** using pytest or the repo's Jest/Vitest runner. Python generation uses LLM/characterization tests; JS/TS scaffolds remain reviewable, unexecuted proposals | repo.read, static.radon, sandbox.execute, llm.generate |
| 3 · Functional Automation | Infers FastAPI/Flask/Express routes, generates journey suites (success, malformed input, auth, 404/405) and runs them in-process in the sandbox; failures become findings | repo.read, sandbox.execute |
| 4 · AWS Cost Optimiser | Inventory and cost model generated only from the repo's Terraform → idle/oversized EC2 & RDS, unattached EBS, old snapshots, idle NAT/ELB, Lambda arm64, S3 tiering; Terraform patches when available | repo.read, terraform.parse, aws.read |
| 5 · Code Health | Radon complexity/MI, Ruff lint, duplication, git churn hotspots; proposes Ruff safe fixes, unused CommonJS binding cleanup, and supported identical aggregation extraction as PR-ready diffs | repo.read, static.ruff, static.radon |
| 6 · Security Guardrails | Secret scanning, dangerous code patterns, Dockerfile/CI/Terraform policies — **and** a deterministic policy engine that validates every proposed change | repo.read, terraform.parse |

**What is real:** repository cloning, OSV lookups, Ruff/Radon, Docker test execution, LLM test drafting and
explanations (Ollama `gemma3` or OpenAI `gpt-4o-mini` via CrewAI — switch providers in Settings), patch
validation and remediation.

**AWS cost data: repository Terraform only.** On every analysis the optimiser generates its own dump from the
current scanned repository. Existing sample/upload selections and legacy `AWS_MODE=live` settings are ignored;
there is no fallback to external data. Upload and sample-selection endpoints are disabled. Supported declarations:
`aws_instance`, `aws_ebs_volume`/`root_block_device`, `aws_db_instance`, `aws_nat_gateway`, `aws_lb`,
`aws_lambda_function`, `aws_s3_bucket` and snapshot declared in the repo becomes inventory, with utilisation and a
CUR modelled deterministically from the declared sizing and list prices. Such a dump sets `simulated: true` in its
manifest, so the UI and every finding are labelled as estimates rather than measurements — and because each
resource carries its Terraform address, the resulting rightsizing / gp2→gp3 / arm64 recommendations come with a
ready-to-review `.tf` patch. No supported resources means an empty inventory and an explicit message, not a sample
account. Generated files are isolated by project and Terraform fingerprint, so changed/removed resources cannot
reuse another revision's inventory. Re-scan existing projects to replace old findings; the AWS page excludes
recommendations from external dumps or a different Terraform fingerprint.

| Generated file | Source |
|---|---|
| `manifest.json` | account, region, period, project tag |
| `cost_and_usage.csv` | Modelled cost for declared resources, using approximate list prices |
| `ec2_instances.json`, `ebs_volumes.json`, `ebs_snapshots.json`, `rds_instances.json`, `nat_gateways.json`, `load_balancers.json`, `lambda_functions.json`, `s3_buckets.json` | Supported Terraform resource declarations only |
| `cloudwatch_metrics.json` | Simulated utilisation assumptions, not observed AWS metrics |

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

LLM: two providers, toggled on the Settings page (or `LLM_PROVIDER` in `.env`). **Ollama** (local, default):
`ollama pull gemma3 && ollama serve`. **OpenAI**: paste the key in Settings → Model provider (stored server-side, returned only masked) or export
`OPENAI_API_KEY`, then pick `gpt-4o-mini` — note that findings then leave the machine. Both benefit from `pip install -e ".[llm]"` for CrewAI. `/api/v1/health` reports
`llm.provider`/`reachable`/`model_available`/`crewai_installed`. Without them, explanations fall back to deterministic
templates and tests to the sandbox-observed characterization strategy.

### Sample repositories (bundled, realistic)

| Repo | Stack | Planted issues |
|---|---|---|
| `fixture:demo-shop` | Flask shop + Express storefront, Terraform, Dockerfile, GitHub Actions | vulnerable pins (requests, urllib3, flask, lodash, axios, express), hard-coded AWS key, `yaml.load`, `verify=False`, `shell=True`, `innerHTML`, open SG, public S3/RDS, CI script injection, complex untested functions |
| `fixture:orders-api` | FastAPI orders service, Terraform (EC2 + 2×RDS), Dockerfile, GitHub Actions | vulnerable pins (fastapi 0.95, starlette, python-multipart, jinja2, cryptography, PyJWT…), hard-coded secrets, SQL f-string injection, pickle/yaml, broken refund authorisation, divide-by-zero report endpoint, `pull_request_target` workflow, oversized/unencrypted/public RDS |

Each repository's Terraform is used to generate its AWS model at scan time, with addresses linking recommendations
back to IaC patches. Legacy files in `fixtures/aws/` are retained for adapter tests only; the optimiser never selects them.

### Demo workflow (no AWS credentials needed)

1. **Add services** → pick a sample (`fixture:demo-shop`, `fixture:orders-api`) or any public GitHub repo, e.g.
   `https://github.com/we45/Vulnerable-Flask-App`. AWS cost data is generated from that repository's Terraform.
2. Open the project → **Run scan**. Watch live progress and agent logs (Server-Sent Events).
3. Open a finding → evidence, explanation, the proposed diff and guardrail checks → **Fix & open PR** (one click:
   approve → apply → verify → draft PR), or step through it manually with **Approve fix** →
   **Apply to isolated branch & verify** → **Push branch & open PR**.
   The patch is committed to an isolated local branch (`skyforge/fix-…`) in a git worktree and re-verified
   (OSV re-query, sandbox test run, Ruff re-check, Terraform syntax, or secret re-scan).
4. Explore Security, Testing, AWS Optimization, Code Health, Agent Center and Settings & Audit.

### Pushing fixes and opening pull requests (GitHub)

SkyForge authenticates to GitHub in one of two ways (first match wins):

1. **GitHub App (preferred).** Set `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID` and `GITHUB_APP_PRIVATE_KEY_PATH`
   (or `GITHUB_APP_PRIVATE_KEY` with the PEM inline). SkyForge signs a short-lived RS256 JWT with the private key and
   exchanges it for a 1-hour installation token, cached in memory only. Install the app on the target repositories
   with *Contents: write* and *Pull requests: write*. Installation tokens cannot create repositories or fork, so the
   sample-repo and fork flows below need a PAT.
2. **Personal access token** in `GITHUB_TOKEN` (fine-grained: *Contents* + *Pull requests* read/write, plus
   *Administration* write to create repos/forks; or a classic token with `repo`).

A per-project `token_secret_ref` overrides both. On a verified fix click **Push branch & open PR**:

| Repository | What happens |
|---|---|
| You have push access (or the app is installed) | `skyforge/fix-…` branch pushed, draft PR against the scanned branch |
| Public repo you don't own | forked to your account, draft PR inside the fork (upstream is never contacted) — PAT only |
| Bundled sample (`fixture:`) | private `skyforge-<name>` repo created in your account, base + fix branch pushed, draft PR — PAT only |

Credentials are only passed to git through environment config (never in arguments, logs or the DB); every push is
audited. `POST /api/v1/findings/{id}/pull-request {"proposal_id": …}` is idempotent.

**One-click Fix.** `POST /api/v1/findings/{id}/fix {"proposal_id": …}` runs the whole chain from a single human
action: guardrail re-validation + approval (recorded against your principal), apply to a `skyforge/fix-…` branch,
verification, then the draft PR. Nothing is relaxed — a guardrail rejection stops it, and the PR is only opened if
verification passes (otherwise `verification.pull_request_error` explains why). For a **Unit Test & Coverage**
finding this means one click generates the tests, proves they pass with measured coverage in the sandbox, and opens
a draft PR whose body lists the before/after coverage and the functions the new tests now exercise.

**Which findings come with a fix.** Every agent can attach a patch, which then flows through the same
validate → approve → apply → verify → draft PR pipeline:

| Agent | Change type | Auto-generated fixes |
|---|---|---|
| Vulnerability | `dependency_upgrade` | Manifest version bump to the nearest non-vulnerable release |
| Unit Test & Coverage / Functional Test | `test_addition`, `functional_test` | Generated suites for uncovered code and API journeys |
| Security Guardrails | `config_fix` | `yaml.load` → `safe_load`, `verify=False`, `debug=True`, `shell=True`, bind `0.0.0.0`, MD5/SHA-1 → SHA-256, `eval()` → `ast.literal_eval()`, `os.system()` → `subprocess.run()`, `innerHTML` → `textContent`, hard-coded secrets → environment |
| Security Guardrails | `iac_change` | Public S3 ACL/public-access block, unencrypted RDS/EBS, publicly reachable RDS, CloudTrail log validation, EC2 public IP |
| Code Health | `refactor` | Python: Ruff safe fixes. JS: unused scalar CommonJS bindings (retains `require` evaluation), and exact supported aggregation clones extracted into an existing initialization-free utility. ESM/destructuring and arbitrary duplicate code are left unchanged |
| AWS Optimizer | `iac_change` | EC2/RDS rightsizing, EBS `gp2` → `gp3`, Lambda `x86_64` → `arm64` |

Patches are capped at 20 files / 2000 changed lines. Rejected proposals offer **Recheck, fix & open PR**:
approval and publishing still require a fresh passing policy result. Secret-bearing patch context is reconstructed
from the original scan in memory; stored/UI diffs remain redacted. JS refactors are verified by replaying supported
transformations against the original commit, not by counting delimiters. Changes that alter behaviour (TLS verification,
hash algorithm, bind address, `innerHTML`) are flagged `breaking` so reviewers see it before approving.

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
  when a human clicks *Push branch & open PR* or *Fix & open PR* on a validated fix (never force-push, never the
  default branch, never without a recorded approval and a passing verification).
- AWS access is read-only by construction (only Describe/Get/List calls), with region and service allow-lists.

## API

All under `/api/v1` (OpenAPI at `/api/docs`): `health`, `dashboard/summary`, `projects` (CRUD),
`projects/{id}/scans`, `scans/{id}`, `scans/{id}/events` (SSE, `?stream=false` for JSON), `scans/{id}/cancel`,
`scans/{id}/artifacts/{artifact_id}`, `findings` (filter/sort/paginate/facets), `findings/{id}`,
`findings/{id}/review`, `findings/{id}/remediate`, `findings/{id}/fix`, `findings/{id}/pull-request`, `agents`, `agents/{id}/runs`, `projects/{id}/aws/resources`,
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

- Coverage measurement and test generation are implemented for Python; JS/TS projects get route inference and a
  generated supertest suite that is not executed.
- Spend comes from the dump's CUR lines; savings combine that spend with static on-demand list prices and are
  labelled estimates. The bundled dumps are realistic samples, not a real account — upload your own export for real
  numbers.
- Local LLMs are slow: a full scan with gemma3 takes a few minutes (explanations + drafted tests). Switching to
  OpenAI `gpt-4o-mini` in Settings is faster but sends finding summaries to the OpenAI API.
- Rate limiting and the worker pool are in-process (single instance). Use PostgreSQL via `DATABASE_URL` for deployment.
- Pull requests are GitHub-only (GitLab/Bitbucket: download the patch artifact).

## Troubleshooting

- *"Docker sandbox unavailable"* — start Docker Desktop; the first sandboxed run pulls `python:3.11-slim` or
  `node:22-slim` (`SANDBOX_NODE_IMAGE`) for JavaScript/TypeScript. JS coverage requires Jest or Vitest in the
  repository's dependencies. Dependency installation is isolated; tests run without network access. Unavailable
  coverage stays unknown, never a fabricated percentage. Code Health includes JS source lines in its duplication
  score; Python-only complexity metrics remain Python-only. Project/dashboard cards retain each agent's latest
  result when a subsequent scan runs unrelated agents.
- *LLM offline* — `ollama serve` and `ollama pull gemma3`, or set another model/provider in Settings.
- *OpenAI "not set"* — paste the key in Settings → Model provider, or export the env var named by
  `OPENAI_API_KEY_ENV` (default `OPENAI_API_KEY`) and restart the API. A key saved in Settings wins over the env var.
- *Repository rejected* — only https URLs on `ALLOWED_GIT_HOSTS` (or `fixture:<name>`) are accepted.
- *Proposal "stale" on approve* — the workspace changed since the scan; re-scan the project.
