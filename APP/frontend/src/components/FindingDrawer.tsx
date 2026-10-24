import { createContext, useContext, useState, type ReactNode } from "react";
import { Drawer, Tooltip } from "@mui/material";
import { useFinding, useHealth, useOpenPullRequest, useRemediate, useReview } from "../api/hooks";
import { ApiError } from "../api/client";
import { AGENT_META, label, money } from "../features/agents";
import type { FindingDetail, Proposal } from "../types";
import { AgentTag, DataTag, DiffView, ErrorState, Icon, Loading, Sev, Status, TimeAgo } from "./common";
import { useToast } from "./Toast";

const Ctx = createContext<(id: string) => void>(() => undefined);
const REVIEW_MSG: Record<string, string> = { accept: "Finding accepted", dismiss: "Finding dismissed", reopen: "Finding reopened",
  approve: "Fix approved — ready to apply", decline: "Fix declined" };
export const useFindingDrawer = () => useContext(Ctx);

export function FindingDrawerProvider({ children }: { children: ReactNode }) {
  const [id, setId] = useState<string | null>(null);
  return (
    <Ctx.Provider value={setId}>
      {children}
      <Drawer anchor="right" open={!!id} onClose={() => setId(null)} PaperProps={{ sx: { width: { xs: "100vw", md: 720 } } }}>
        {id && <FindingPanel id={id} onClose={() => setId(null)} />}
      </Drawer>
    </Ctx.Provider>
  );
}

function FindingPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { data: f, isLoading, error } = useFinding(id);
  const review = useReview(id);
  const toast = useToast();
  const act = (decision: string, proposal_id?: string) =>
    review.mutate({ decision, proposal_id }, {
      onSuccess: () => toast(REVIEW_MSG[decision] ?? "Saved", "var(--orchid)"),
      onError: (e) => toast(errMsg(e), "var(--tomato)"),
    });
  return (
    <div style={{ padding: 26 }} className="stack">
      <div className="row" style={{ alignItems: "flex-start" }}>
        <div style={{ flex: 1 }}>
          {f && (
            <div className="row wrap" style={{ gap: 8, marginBottom: 8 }}>
              <Sev s={f.severity} />
              <Status s={f.status} />
              <AgentTag id={f.source_agent} />
              <DataTag source={f.data_source} />
              <span className="mono dim">{f.id}</span>
            </div>
          )}
          <h2 style={{ fontSize: "1.35rem" }}>{f?.title ?? "Loading…"}</h2>
          {f && (
            <p className="muted mono">
              {f.project_name} · {f.target}
              {f.location?.line ? `:${f.location.line}` : ""}
            </p>
          )}
        </div>
        <button className="icon-btn" onClick={onClose} aria-label="Close">
          <Icon name="close" />
        </button>
      </div>
      {isLoading && <Loading rows={5} />}
      {error && <ErrorState error={error} />}
      {f && (
        <>
          <div className="explain">
            <div className="row" style={{ marginBottom: 6 }}>
              <b>Explanation</b>
              <span className="tag tag-est">{f.explanation_source === "template" ? "deterministic" : f.explanation_source}</span>
            </div>
            {f.explanation || f.description}
          </div>
          {f.description && f.description !== f.explanation && <p style={{ fontSize: ".9rem" }}>{f.description}</p>}
          <div className="panel">
            <b>Recommendation</b>
            <p style={{ marginTop: 4 }}>{f.recommendation || "—"}</p>
            {f.estimated_monthly_savings != null && (
              <p style={{ marginTop: 8 }}>
                Estimated saving <span className="money">{money(f.estimated_monthly_savings, 2)}</span>/month <DataTag source={f.data_source} />
              </p>
            )}
          </div>
          <div className="row wrap">
            <button className="btn btn-ghost btn-sm" disabled={review.isPending || f.status === "accepted"} onClick={() => act("accept")}>Accept risk / track</button>
            <button className="btn btn-ghost btn-sm" disabled={review.isPending || f.status === "dismissed"} onClick={() => act("dismiss")}>Dismiss</button>
            {["dismissed", "fixed", "verified", "accepted"].includes(f.status) && (
              <button className="btn btn-ghost btn-sm" disabled={review.isPending} onClick={() => act("reopen")}>Reopen</button>
            )}
          </div>
          <Evidence f={f} />
          <section className="stack" style={{ gap: 12 }}>
            <h3>Proposed fix</h3>
            {f.proposals.length === 0 && <div className="panel dim">No automated fix for this finding — follow the recommendation above.</div>}
            {f.proposals.map((p) => (
              <ProposalCard key={p.id} p={p} findingId={f.id} onReview={act} busy={review.isPending} />
            ))}
          </section>
          {f.approvals.length > 0 && (
            <section>
              <h3 style={{ marginBottom: 8 }}>Approval history</h3>
              <table className="table">
                <tbody>
                  {f.approvals.map((a) => (
                    <tr key={a.id}>
                      <td><Status s={a.decision === "approve" ? "approved" : a.decision === "decline" ? "declined" : a.decision} text={a.decision} /></td>
                      <td>{a.actor}</td>
                      <td className="dim">{a.comment || "—"}</td>
                      <td className="dim"><TimeAgo iso={a.created_at} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
          {f.test_runs.length > 0 && (
            <section>
              <h3 style={{ marginBottom: 8 }}>Test results ({AGENT_META[f.source_agent]?.code})</h3>
              <table className="table">
                <tbody>
                  {f.test_runs.map((t) => (
                    <tr key={t.id}>
                      <td><Status s={t.status} /></td>
                      <td>{t.details?.label ?? t.kind}</td>
                      <td>{t.passed}/{t.total} passed</td>
                      <td>{t.coverage_after != null ? `${t.coverage_after}% cov` : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </>
      )}
    </div>
  );
}

function errMsg(e: unknown) {
  if (e instanceof ApiError) {
    const det = Array.isArray(e.details) ? ` — ${(e.details as any[]).map((d) => d.name ?? d.msg).join(", ")}` : "";
    return `${e.message}${det}`;
  }
  return (e as Error).message;
}

function ProposalCard({ p, findingId, onReview, busy }: { p: Proposal; findingId: string; onReview: (d: string, pid?: string) => void; busy: boolean }) {
  const remediate = useRemediate(findingId);
  const openPr = useOpenPullRequest(findingId);
  const { data: health } = useHealth();
  const pr = p.verification?.pull_request;
  const toast = useToast();
  const checks = p.validation?.checks ?? [];
  const vchecks = p.verification?.checks ?? [];
  return (
    <div className="card" style={{ padding: 18 }}>
      <div className="row wrap" style={{ marginBottom: 8 }}>
        <b style={{ flex: 1 }}>{p.title}</b>
        <span className="tag tag-est">{label(p.kind)}</span>
        {p.breaking && <span className="tag" style={{ background: "var(--tomato-t)", color: "#D63C3C" }}>breaking</span>}
        <Status s={p.status} />
      </div>
      {p.summary && <p className="muted" style={{ marginBottom: 10 }}>{p.summary}</p>}
      <DiffView diff={p.diff} />
      <div style={{ margin: "12px 0 6px", fontWeight: 700, fontSize: ".85rem" }}>
        Guardrail validation {p.validation?.policy_version && <span className="dim mono">policy {p.validation.policy_version}</span>}
      </div>
      <div className="checks">
        {checks.map((c) => (
          <Tooltip key={c.name} title={c.detail}>
            <div className={`check ${c.passed ? "ok" : "bad"}`}>
              <span>{c.passed ? "✓" : "✕"}</span>
              <div>{label(c.name)}<small>{c.detail.slice(0, 80)}</small></div>
            </div>
          </Tooltip>
        ))}
      </div>
      {(p.branch || vchecks.length > 0 || p.verification?.error) && (
        <div className="panel" style={{ marginTop: 12 }}>
          <div className="row wrap" style={{ marginBottom: 6 }}>
            <b>Verification</b>
            {p.verification?.status && <Status s={p.verification.status} />}
            {p.branch && <span className="mono">branch {p.branch}</span>}
            {p.commit_sha && <span className="mono dim">{p.commit_sha.slice(0, 10)}</span>}
          </div>
          {p.verification?.summary && <p style={{ fontSize: ".86rem" }}>{p.verification.summary}</p>}
          {p.verification?.error && <p className="form-msg err">{p.verification.error}</p>}
          <div className="checks" style={{ marginTop: 8 }}>
            {vchecks.map((c) => (
              <div key={c.name} className={`check ${c.passed ? "ok" : "bad"}`}>
                <span>{c.passed ? "✓" : "✕"}</span>
                <div>{label(c.name)}<small>{c.detail}</small></div>
              </div>
            ))}
          </div>
          {p.verification?.rollback && <p className="mono dim" style={{ marginTop: 8 }}>Rollback: {p.verification.rollback}</p>}
          {pr && (
            <p style={{ marginTop: 8 }}>
              Draft PR <a href={pr.url} target="_blank" rel="noopener noreferrer"><b>#{pr.number}</b> in {pr.repo}</a>
              <span className="dim"> · {pr.mode === "fork" ? "opened in your fork" : pr.mode === "sample-repo" ? "private demo repo" : "same repository"}</span>
            </p>
          )}
        </div>
      )}
      <div className="modal-actions" style={{ marginTop: 14 }}>
        {["validated", "approved", "rejected_by_policy"].includes(p.status) && (
          <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => onReview("decline", p.id)}>Decline</button>
        )}
        {(p.status === "validated" || p.status === "declined") && (
          <button className="btn btn-primary btn-sm" disabled={busy} onClick={() => onReview("approve", p.id)}>Approve fix</button>
        )}
        {["approved", "apply_failed", "verification_failed"].includes(p.status) && (
          <button className="btn btn-ink btn-sm" disabled={remediate.isPending}
            onClick={() => remediate.mutate(p.id, { onSuccess: () => toast("Applying in an isolated branch and verifying…", "var(--cobalt)"), onError: (e) => toast(errMsg(e), "var(--tomato)") })}>
            {p.status === "approved" ? "Apply to isolated branch & verify" : "Retry apply & verify"}
          </button>
        )}
        {p.status === "applying" && <span className="row"><span className="spinner" /> Applying &amp; verifying…</span>}
        {["verified", "applied"].includes(p.status) && p.branch && !pr && (
          <Tooltip title={health?.github_publish ? "Pushes the fix branch and opens a draft pull request on GitHub" : "Set GITHUB_TOKEN on the server to enable"}>
            <span>
              <button className="btn btn-primary btn-sm" disabled={openPr.isPending || !health?.github_publish}
                onClick={() => openPr.mutate(p.id, { onSuccess: (r) => toast(`Draft PR #${r.number} opened in ${r.repo}`, "var(--teal)"), onError: (e) => toast(errMsg(e), "var(--tomato)") })}>
                {openPr.isPending ? "Pushing…" : "Push branch & open PR"}
              </button>
            </span>
          </Tooltip>
        )}
        {pr && <a className="btn btn-ghost btn-sm" href={pr.url} target="_blank" rel="noopener noreferrer">View PR #{pr.number}</a>}
      </div>
    </div>
  );
}

function Evidence({ f }: { f: FindingDetail }) {
  const ev = f.evidence || {};
  if (f.source_agent === "vulnerability" && Array.isArray(ev.advisories)) {
    return (
      <section>
        <h3 style={{ marginBottom: 8 }}>Advisories for {ev.package} {ev.installed_version}</h3>
        <table className="table">
          <thead><tr><th>Advisory</th><th>Severity</th><th>CVSS</th><th>Fixed in</th><th>Summary</th></tr></thead>
          <tbody>
            {ev.advisories.map((a: any) => (
              <tr key={a.id}>
                <td className="mono">{a.id}<div className="dim">{(a.aliases || []).slice(0, 2).join(", ")}</div></td>
                <td><Sev s={a.severity} /></td>
                <td>{a.cvss ?? "—"}</td>
                <td className="mono">{(a.fixed_in || []).join(", ") || "—"}</td>
                <td style={{ fontSize: ".8rem" }}>{a.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    );
  }
  if (f.category === "cost") {
    return (
      <section className="panel">
        <dl className="kv">
          <dt>Resource</dt><dd className="mono">{ev.resource?.id} ({ev.resource?.type})</dd>
          <dt>Scope</dt><dd>{ev.scope?.account_id} · {(ev.scope?.regions || []).join(", ")} · {ev.scope?.mode}</dd>
          <dt>Observed ({ev.period_days}d)</dt><dd className="mono">{JSON.stringify(ev.observed)}</dd>
          <dt>Calculation</dt><dd className="mono">{ev.calculation}</dd>
          <dt>Savings type</dt><dd>{ev.savings_type} · {ev.pricing}</dd>
          <dt>Confidence</dt><dd>{f.confidence}</dd>
        </dl>
      </section>
    );
  }
  return (
    <section>
      <h3 style={{ marginBottom: 8 }}>Evidence</h3>
      <pre className="json">{JSON.stringify(ev, null, 2)}</pre>
    </section>
  );
}
