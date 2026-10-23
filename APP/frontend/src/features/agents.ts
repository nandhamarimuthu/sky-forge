import type { AgentId } from "../types";

export interface AgentMeta {
  id: AgentId;
  code: string;
  short: string;
  name: string;
  num: string;
  c: string;
  t: string;
  hex: string;
}

export const AGENT_META: Record<AgentId, AgentMeta> = {
  vulnerability: { id: "vulnerability", code: "Vulnerability Remediation", short: "Vuln", name: "Vulnerability Remediation", num: "01", c: "var(--tomato)", t: "var(--tomato-t)", hex: "#FF5A5A" },
  unit_test: { id: "unit_test", code: "Unit Test & Coverage", short: "Coverage", name: "Unit Test & Coverage", num: "02", c: "var(--cobalt)", t: "var(--cobalt-t)", hex: "#4361EE" },
  functional_test: { id: "functional_test", code: "Functional Automation", short: "Functional", name: "Functional Automation", num: "03", c: "var(--orchid)", t: "var(--orchid-t)", hex: "#9157FF" },
  aws_optimizer: { id: "aws_optimizer", code: "AWS Cost Optimiser", short: "AWS Cost", name: "AWS Cost Optimiser", num: "04", c: "var(--teal)", t: "var(--teal-t)", hex: "#0EB5A8" },
  code_health: { id: "code_health", code: "Code Health", short: "Health", name: "Code Health", num: "05", c: "var(--sun)", t: "var(--sun-t)", hex: "#FFAE1A" },
  guardrails: { id: "guardrails", code: "Security Guardrails", short: "Guardrails", name: "Security Guardrails", num: "G", c: "var(--mint)", t: "var(--mint-t)", hex: "#16C47F" },
};
export const AGENT_ORDER: AgentId[] = ["vulnerability", "unit_test", "functional_test", "aws_optimizer", "code_health", "guardrails"];
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const AVATAR_COLORS = ["#FF5A5A", "#4361EE", "#9157FF", "#0EB5A8", "#F2479A", "#FFAE1A", "#16C47F"];

export function hashColor(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

export const money = (n: number | null | undefined, digits = 0) =>
  n === null || n === undefined ? "—" : "$" + n.toLocaleString("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits });

export function timeAgo(iso?: string | null, now: number = Date.now()): string {
  if (!iso) return "—";
  const s = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const label = (s: string) => s.replace(/_/g, " ");
