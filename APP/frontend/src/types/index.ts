export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AgentId = "vulnerability" | "unit_test" | "functional_test" | "aws_optimizer" | "code_health" | "guardrails";

export interface Page<T> { items: T[]; total: number; page: number; page_size: number }

export interface AgentRun {
  id: string; scan_id: string; project_id: string; agent_id: AgentId; status: string; progress: number;
  attempts: number; metrics: Record<string, any>; tools_used: string[]; findings_count: number;
  error: string | null; started_at: string | null; finished_at: string | null;
}

export interface Scan {
  id: string; project_id: string; status: string; agents: AgentId[]; options: Record<string, any>;
  requested_by: string; progress: number; commit_sha: string | null; summary: Record<string, any>;
  error: string | null; created_at: string; started_at: string | null; finished_at: string | null;
  agent_runs: AgentRun[]; project_name?: string | null;
}

export interface Project {
  id: string; name: string; description: string; language: string;
  scan_scope: AgentId[]; created_by: string; created_at: string;
  repository: { provider: string; url: string; owner: string; name: string; branch: string | null; last_commit: string | null; has_token_ref: boolean } | null;
  cloud_account: { provider: string; account_id: string; project_tag: string; regions: string[]; services: string[]; mode: string } | null;
  stats: { open_by_severity: Record<string, number>; open_total: number; estimated_monthly_savings: number; coverage: number | null; coverage_before: number | null; health_score: number | null; vulnerabilities: number };
  last_scan: Scan | null;
}

export interface Finding {
  id: string; project_id: string; scan_id: string; source_agent: AgentId; category: string; rule_id: string;
  severity: Severity; title: string; description: string; target: string; location: Record<string, any>;
  recommendation: string; status: string; confidence: string; data_source: "measured" | "estimated" | "simulated";
  estimated_monthly_savings: number | null; created_at: string; updated_at: string; last_seen_at: string;
  has_proposal: boolean; project_name?: string | null;
}

export interface Proposal {
  id: string; finding_id: string; agent_id: AgentId; kind: string; title: string; summary: string; diff: string;
  files: string[]; breaking: boolean; status: string; validation: { passed?: boolean; checks?: Check[]; policy_version?: string; breaking_change?: boolean };
  verification: { status?: string; checks?: Check[]; summary?: string; rollback?: string; error?: string;
    pull_request_error?: string;
    pull_request?: { url: string; number: number; repo: string; mode: string; branch: string; base: string } };
  branch: string | null; base_commit: string | null; commit_sha: string | null; created_at: string; updated_at: string;
}
export interface Check { name: string; passed: boolean; detail: string }

export interface TestRun {
  id: string; scan_id: string; project_id: string; agent_id: string; kind: string; framework: string; status: string;
  total: number; passed: number; failed: number; errors: number; skipped: number; coverage_before: number | null;
  coverage_after: number | null; duration_s: number | null; details: Record<string, any>; report_artifact_id: string | null;
  created_at: string; project_name?: string;
}

export interface FindingDetail extends Finding {
  evidence: Record<string, any>; explanation: string; explanation_source: string; validation: Record<string, any>;
  proposals: Proposal[]; approvals: { id: string; decision: string; actor: string; comment: string; created_at: string; proposal_id: string | null }[];
  test_runs: TestRun[];
}

export interface FindingPage extends Page<Finding> { facets: Record<string, Record<string, number>> }

export interface ScanEvent {
  id: number; scan_id: string; ts: string; type: string; agent_id: AgentId | null; level: string; message: string;
  progress: number | null; data: Record<string, any>;
}

export interface AgentInfo {
  id: AgentId; name: string; code: string; description: string; allowed_tools: string[];
  tools: { name: string; description: string; available: boolean }[]; runs_by_status: Record<string, number>;
  open_findings: number; status: string;
}

export interface Artifact { id: string; scan_id: string; agent_id: string | null; kind: string; name: string; media_type: string; size: number; created_at: string }
