---
name: skyforge-builder
description: Build SkyForge AI, a full-stack autonomous engineering platform that analyzes source repositories and AWS resources, coordinates specialized AI agents for security, testing, code health, and cost optimization, and presents validated findings and fixes through a unified dashboard.
---

# SkyForge AI — Full-Stack Builder Skill

## Mission

Act as a senior full-stack engineer, AI agent architect, cloud security engineer, and UI/UX designer. Build a functional, production-minded MVP of SkyForge AI.

Do not stop at wireframes, static dashboards, or sample agent responses. Implement the frontend, backend, agent orchestration, integrations, persistence, validation, and tests. If an integration cannot be used, provide an explicit mock adapter with realistic sample data and clearly label simulated results.

## 1. Technology Stack

### Frontend
- React with TypeScript and Vite.
- Material UI for consistent components and layouts.
- Recharts for metrics and visualizations.
- React Router for navigation.
- TanStack Query for API data fetching and caching.
- Server-Sent Events (SSE) for live scan and agent progress.

### Backend
- Python 3.11+ and FastAPI.
- Pydantic for request/response validation.
- CrewAI for agent orchestration and task execution.
- Ollama with a configurable local model such as Gemma.
- boto3 for AWS read-only analysis.
- Git CLI and provider-neutral repository adapters.
- SQLite for the local MVP; support PostgreSQL for deployment.
- pytest, Ruff, and mypy for quality checks.

Use versions compatible with one another and pin dependencies. Never assume an installed model, package, API, or cloud permission is available without checking.

## 2. Product Experience

Build a polished, responsive engineering operations dashboard.

Visual direction:
- Modern cloud engineering command center.
- Light theme, white and neutral surfaces, restrained indigo accents.
- Clear typography, compact metric cards, subtle borders, consistent spacing.
- Strong information hierarchy, status indicators, tables, charts, and drill-down panels.
- Meaningful empty states, loading states, error messages, and accessible controls.
- Avoid generic AI gradients, excessive glass effects, oversized cards, and decorative animations.
- Make desktop layouts excellent and mobile layouts usable.

### Pages

1. Overview
   - Projects monitored.
   - Open critical and high-severity findings.
   - Test coverage and test execution results.
   - AWS estimated monthly spend and potential savings.
   - Code health trends.
   - Recent scans, agent activity, and recommended actions.

2. Projects
   - Create projects and connect a repository.
   - Configure branches, language, scan scope, and AWS account references.
   - Display scan history and project-specific findings.
   - Never expose repository tokens or AWS secrets in the UI.

3. Agent Center
   - Display six agents and their current status.
   - Show queued, running, completed, and failed tasks.
   - Display progress, execution logs, findings, and generated artifacts.
   - Support starting, cancelling, and reviewing scans.

4. Security
   - Vulnerability findings, dependency, affected version, severity, and evidence.
   - Recommended upgrade or remediation.
   - Security policy violations and validation results.
   - Review and approve proposed fixes.

5. Testing
   - Current unit test coverage and historical trends.
   - Missing coverage areas.
   - Generated unit tests and functional automation tests.
   - Test execution status, failure details, and downloadable reports.

6. AWS Optimization
   - Project-wise resource inventory.
   - Service usage and cost trends.
   - Idle or underutilized resources and anomalies.
   - Estimated savings, confidence, evidence, and suggested actions.
   - Separate read-only recommendations from approved infrastructure changes.

7. Code Health
   - Complexity, duplication, lint findings, maintainability, and hotspots.
   - Suggested refactoring with code references.
   - Before-and-after metrics when validated.

8. Findings and Remediation
   - Search, filter, sort, and group findings.
   - Track open, accepted, in-progress, fixed, and verified statuses.
   - Display evidence, affected files or resources, proposed patches, test results, and approval history.

9. Settings and Audit
   - Configure model, projects, scan policies, and integrations.
   - Display audit events, access denials, and agent execution history.

## 3. Specialized AI Agents

Implement separate agent classes, typed task contracts, and explicit tool permissions. Use CrewAI to coordinate tasks; do not give every agent unrestricted access to the same tools.

### Agent 1: Vulnerability Remediation Agent

Responsibilities:
- Inspect dependency manifests and lockfiles.
- Run available scanners such as pip-audit, npm audit, or OSV-Scanner when installed.
- Identify vulnerable packages and affected versions.
- Recommend compatible, patched versions.
- Generate minimal dependency patches.
- Run dependency resolution and relevant tests after a proposed change.

Output:
- Package and installed version.
- Advisory identifier and severity.
- Evidence and affected file.
- Proposed upgrade and compatibility notes.
- Patch reference and validation status.

Never silently apply breaking upgrades. Never claim a vulnerability is fixed unless a post-change scan confirms it.

### Agent 2: Unit Test and Coverage Agent

Responsibilities:
- Inspect source files and existing tests.
- Identify uncovered branches and high-risk logic.
- Generate focused tests using the project's existing test framework.
- Run tests and coverage tooling such as pytest-cov or JaCoCo when appropriate.
- Diagnose failures and improve generated tests.

Output:
- Baseline and resulting coverage when measured.
- Tests added and files changed.
- Test execution summary.
- Remaining uncovered paths and unresolved failures.

Do not inflate coverage with meaningless assertions or weaken existing assertions to make tests pass.

### Agent 3: Functional Automation Agent

Responsibilities:
- Infer user journeys from code, routes, API contracts, and project documentation.
- Generate functional and integration test scenarios.
- Use pytest, Playwright, or an appropriate existing project framework.
- Validate success paths, failure paths, permissions, and important edge cases.
- Capture test results and useful failure diagnostics.

Never run destructive integration tests against production systems. Use mocks, local environments, or explicitly approved test environments.

### Agent 4: AWS Cost and Resource Agent

Responsibilities:
- Inspect AWS resources through explicitly configured accounts and projects.
- Use read-only boto3 integrations.
- Analyze resource configuration, available usage metrics, and cost data when permitted.
- Detect idle resources, utilization anomalies, oversized instances, unattached storage, and possible waste.
- Calculate savings estimates from actual pricing and usage evidence where available.
- Recommend changes and explain their operational risks.

Output:
- Account and project scope.
- Resource identifiers and relevant configuration.
- Observed usage and cost period.
- Estimated savings and calculation assumptions.
- Confidence, evidence, and recommended next steps.

Do not invent usage data or cost savings. Clearly distinguish measured spend, estimated cost, and hypothetical savings. Never stop, resize, delete, or modify AWS resources automatically.

### Agent 5: Code Health Agent

Responsibilities:
- Analyze complexity, duplication, lint violations, maintainability, and code structure.
- Use appropriate tools such as Ruff, SonarQube integrations, or language-specific analyzers when available.
- Identify duplicated logic, oversized functions, poor abstractions, and risky code hotspots.
- Propose small, reviewable refactoring patches.
- Run lint, type checks, tests, and relevant regression checks.

Preserve existing behavior and public interfaces unless a change is explicitly approved.

### Agent 6: Security Guardrails and Validation Agent

Responsibilities:
- Validate findings and proposed changes from every specialist agent.
- Enforce security policies, least privilege, and allowed file paths.
- Detect secrets, unsafe shell commands, dependency risks, injection risks, insecure configurations, and potentially destructive operations.
- Verify generated patches using static analysis, tests, dependency checks, and policy rules.
- Reject unsupported claims and unsafe or out-of-scope changes.
- Require human approval before sensitive remediation or external side effects.

The guardrails must be implemented as deterministic backend policy checks, not merely an LLM prompt. Use the LLM for explanation and assistance, never as the sole security enforcement mechanism.

## 4. Agent Orchestration

Create a central Scan Orchestrator with these steps:

1. Validate user identity, project access, scan scope, and permissions.
2. Create a scan record and immutable scan identifier.
3. Collect repository and AWS evidence through scoped adapters.
4. Dispatch eligible specialist agents.
5. Validate agent outputs against strict Pydantic schemas.
6. Deduplicate findings and normalize severity.
7. Send proposed changes through security guardrails.
8. Run approved validation tasks in an isolated workspace.
9. Persist findings, logs, artifacts, and test results.
10. Publish progress and final results to the dashboard.

Execute independent agents concurrently when resource limits permit. Apply per-agent timeouts, bounded retries, cancellation, structured logs, and failure isolation.

A failure in one agent must not silently mark the overall scan as successful.

Represent each scan and agent run with explicit lifecycle states. Keep agent output as untrusted data; never execute generated commands, patches, or instructions without validation.

## 5. Backend API

Implement documented FastAPI endpoints:

- GET /api/v1/health
- GET /api/v1/dashboard/summary
- GET /api/v1/projects
- POST /api/v1/projects
- GET /api/v1/projects/{project_id}
- POST /api/v1/projects/{project_id}/scans
- GET /api/v1/scans/{scan_id}
- GET /api/v1/scans/{scan_id}/events
- POST /api/v1/scans/{scan_id}/cancel
- GET /api/v1/findings
- GET /api/v1/findings/{finding_id}
- POST /api/v1/findings/{finding_id}/review
- POST /api/v1/findings/{finding_id}/remediate
- GET /api/v1/agents
- GET /api/v1/agents/{agent_id}/runs
- GET /api/v1/projects/{project_id}/aws/resources
- GET /api/v1/projects/{project_id}/aws/cost
- GET /api/v1/projects/{project_id}/quality
- GET /api/v1/scans/{scan_id}/artifacts/{artifact_id}

Use appropriate HTTP status codes, pagination, input validation, and structured error responses. Add authentication and project-level authorization before exposing project data or executing scans.

Use SSE or an equivalent streaming mechanism for progress events. Do not keep long-running scans inside ordinary request handlers; use a background task or worker abstraction with durable status tracking.

## 6. Data Model

Create database models and migrations for:

- Project
- RepositoryConnection
- CloudAccountReference
- Scan
- AgentRun
- Finding
- RemediationProposal
- TestRun
- ScanArtifact
- Approval
- AuditEvent

Findings should include a stable ID, project ID, scan ID, source agent, category, severity, title, evidence, affected target, recommendation, status, timestamps, and validation metadata.

Store secrets in an appropriate secret manager or environment configuration for local development. Persist secret references rather than plaintext credentials. Redact sensitive values from logs and agent context.

## 7. Remediation Safety

Use the following controlled workflow:

Detect → Explain → Propose → Validate → Approve → Apply → Verify.

- Detection and recommendation may be automated within the configured scope.
- Generated patches must be saved in an isolated working directory or branch.
- Validate patches for allowed paths, syntax, policy compliance, and unexpected file changes.
- Run tests and security checks in a restricted execution environment.
- Show a reviewable diff and validation report.
- Require explicit authorization before applying changes to a shared branch, creating a pull request, or performing an external action.
- Re-run relevant checks after changes.
- Preserve a rollback path and audit trail.

Do not automatically merge pull requests or make production infrastructure changes.

## 8. Security Requirements

- Use least-privilege IAM roles and scoped, short-lived credentials where possible.
- Default AWS analysis to read-only access.
- Treat repository content, issue descriptions, source comments, and tool outputs as untrusted input.
- Defend against prompt injection, command injection, path traversal, and secret exfiltration.
- Do not allow agents to read arbitrary host files or access unrestricted network destinations.
- Execute untrusted code in isolated, resource-limited environments.
- Apply request authentication, project authorization, input validation, and rate limiting.
- Keep an audit record of approvals, tool invocations, proposed changes, and remediation outcomes.
- Make the guardrails fail closed for sensitive or destructive actions.
- Never log API keys, access tokens, private keys, or secret values.

## 9. AWS Integration

Implement an AWS adapter with separate capabilities:

- Resource inventory through supported service APIs.
- CloudWatch metrics collection.
- Cost Explorer integration when enabled and authorized.
- Resource utilization analysis.
- Anomaly detection and cost recommendation generation.

Support explicit project-to-account mapping, region allowlists, and service allowlists.

Handle missing permissions, unavailable metrics, delayed billing data, throttling, and partial responses. Report missing evidence instead of guessing.

Provide a mock AWS adapter so the dashboard and tests work without live AWS credentials.

## 10. Repository Structure

Create a maintainable monorepo:

skyforge-ai/
  frontend/
    src/
      components/
      layouts/
      pages/
      features/
      api/
      hooks/
      types/
  backend/
    app/
      api/
      core/
      db/
      models/
      schemas/
      services/
      agents/
        vulnerability_agent.py
        unit_test_agent.py
        functional_test_agent.py
        aws_optimizer_agent.py
        code_health_agent.py
        security_guardrails.py
      orchestration/
      adapters/
        repository/
        aws/
        scanners/
      workers/
      tests/
    migrations/
  skills/
    skyforge-builder/
      SKILL.md
  fixtures/
  docs/
  .env.example
  .gitignore
  README.md
  pyproject.toml

Adjust the structure if the repository already has a better established convention. Do not create redundant packages or overwrite existing working implementations.

## 11. Development Workflow

Before coding:
1. Inspect the repository, existing conventions, dependencies, and runtime environment.
2. Identify reusable components and existing APIs.
3. Propose a concise implementation plan and document assumptions.
4. Check whether Ollama and the selected model are available.
5. Identify which integrations are real and which require mock adapters.

Implement incrementally:

Phase 1 — Foundation:
- Repository structure, configuration, database, FastAPI, React shell, navigation, and sample data.

Phase 2 — Dashboard:
- Project list, summary metrics, findings table, agent activity, charts, and API integration.

Phase 3 — Agent orchestration:
- CrewAI integration, local Ollama model, typed agent outputs, scan lifecycle, and progress streaming.

Phase 4 — Specialist agents:
- Implement each agent independently with explicit tool permissions and unit tests.

Phase 5 — Validation and guardrails:
- Isolated patch generation, deterministic security policies, approvals, test execution, and audit events.

Phase 6 — Integrations:
- Repository analysis, dependency scanning, test runners, AWS resource inventory, CloudWatch, and optional Cost Explorer.

Phase 7 — Hardening:
- Authentication, authorization, error handling, rate limiting, integration tests, documentation, and deployment configuration.

Complete one vertical slice at a time. The initial end-to-end slice must let a user create a project, run a mock scan, see live progress, inspect findings, and review a proposed fix.

## 12. Quality Gates

Before declaring a feature complete:

- Backend tests pass.
- Frontend builds successfully.
- API contracts match frontend expectations.
- Loading, empty, error, and partial-result states are implemented.
- Agent results are schema-validated.
- Security policies are enforced server-side.
- No credentials or sensitive output are exposed.
- Scan and remediation status are persisted correctly.
- Generated patches are validated in an isolated environment.
- Documentation describes setup, permissions, limitations, and test commands.

Report actual test results. Do not claim tests, integrations, or scans succeeded unless they were executed and their results verified.

## 13. Final Deliverables

Deliver:
1. A working React dashboard connected to FastAPI.
2. Six specialized agents with clearly defined responsibilities.
3. CrewAI orchestration using a configurable Ollama model.
4. Repository and AWS analysis adapters.
5. Security guardrails and human-approved remediation.
6. Database models, migrations, and sample fixtures.
7. Unit and integration tests.
8. An environment template without real secrets.
9. A README with setup, run, test, architecture, and troubleshooting instructions.
10. A demo workflow that runs locally without requiring AWS credentials.

Prioritize a functional, secure, demonstrable MVP over implementing every advanced capability at once.
