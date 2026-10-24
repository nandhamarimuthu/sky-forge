import { useState } from "react";
import { useAgentRuns, useAgents, useProjects } from "../api/hooks";
import { Empty, ErrorState, Loading, Status, TimeAgo } from "../components/common";
import { PageHead } from "../components/PageHead";
import { ScanProgress } from "../components/Scan";
import { AGENT_META, formatDuration } from "../features/agents";
import type { AgentId } from "../types";

const duration = (a?: string | null, b?: string | null) =>
  a && b ? formatDuration((new Date(b).getTime() - new Date(a).getTime()) / 1000) : "—";

export function AgentCenterPage() {
  const { data, isLoading, error } = useAgents();
  const [selected, setSelected] = useState<AgentId>("vulnerability");
  const { data: runs } = useAgentRuns(selected);
  const { data: projects } = useProjects();
  const [scanId, setScanId] = useState<string | null>(null);
  const names = Object.fromEntries((projects?.items ?? []).map((p) => [p.id, p.name]));

  return (
    <>
      <PageHead eyebrow="Agent Center" title="Your" highlight="agent crew"
        sub="Each agent has an explicit tool allow-list. Guardrails validates every proposed change deterministically — the LLM never enforces policy." />
      {error ? <ErrorState error={error} /> : isLoading || !data ? <Loading rows={2} height={160} /> : (
        <div className="agents-grid">
          {data.map((a) => {
            const m = AGENT_META[a.id];
            const busy = a.status === "running";
            const total = Object.values(a.runs_by_status).reduce((x, y) => x + y, 0);
            return (
              <article key={a.id} className={`agent click ${selected === a.id ? "sel" : ""}`}
                style={{ ["--c" as any]: m.c, ["--t" as any]: m.t }} onClick={() => { setSelected(a.id); setScanId(null); }}>
                <div className="agent-top">
                  <div className="agent-num">{m.num}</div>
                  <div style={{ flex: 1 }}><div className="agent-code">{m.short}</div><div className="agent-name">{a.name}</div></div>
                  {busy ? <span className="spinner" /> : <span className="dim" style={{ fontSize: ".78rem" }}>{a.status}</span>}
                </div>
                <div className="agent-body">
                  <p className="agent-desc">{a.description}</p>
                  <div className="agent-stats">
                    <div><b>{a.open_findings}</b><span>open findings</span></div>
                    <div><b>{a.runs_by_status.completed ?? 0}</b><span>completed</span></div>
                    <div><b>{(a.runs_by_status.failed ?? 0) + (a.runs_by_status.timed_out ?? 0)}</b><span>failed</span></div>
                  </div>
                  <div className="row wrap" style={{ gap: 5 }}>
                    {a.tools.map((t) => (
                      <span key={t.name} className={`tool ${t.available ? "" : "off"}`} title={`${t.description}${t.available ? "" : " — unavailable"}`}>{t.name}</span>
                    ))}
                  </div>
                  <div className="muted" style={{ fontSize: ".76rem" }}>{total} run(s) · queued {a.runs_by_status.queued ?? 0} · running {a.runs_by_status.running ?? 0} · cancelled {a.runs_by_status.cancelled ?? 0}</div>
                </div>
              </article>
            );
          })}
        </div>
      )}

      <div className="card">
        <div className="card-head">
          <div><h2>{AGENT_META[selected].name} · runs</h2><p className="muted">Click a run to open its scan log, progress and controls</p></div>
        </div>
        {!runs?.items.length ? <Empty title="No runs yet">Start a scan from a project to see this agent at work.</Empty> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Project</th><th>Status</th><th>Progress</th><th>Findings</th><th>Key metrics</th><th>Duration</th><th>Started</th></tr></thead>
              <tbody>
                {runs.items.map((r) => (
                  <tr key={r.id} className="click" onClick={() => setScanId(r.scan_id)} style={scanId === r.scan_id ? { background: "var(--orchid-t)" } : undefined}>
                    <td><b>{names[r.project_id] ?? r.project_id}</b><div className="mono dim" style={{ fontSize: ".72rem" }}>{r.scan_id.slice(-8)}</div></td>
                    <td><Status s={r.status} />{r.error && <div className="muted" style={{ fontSize: ".72rem", maxWidth: 260 }}>{r.error.slice(0, 120)}</div>}</td>
                    <td><div className="progress" style={{ width: 100 }}><span style={{ width: `${Math.round(r.progress * 100)}%` }} /></div></td>
                    <td>{r.findings_count}</td>
                    <td className="mono" style={{ fontSize: ".74rem" }}>
                      {Object.entries(r.metrics).filter(([, v]) => typeof v === "number" || typeof v === "boolean").slice(0, 4).map(([k, v]) => <div key={k}>{k}: {String(v)}</div>)}
                    </td>
                    <td>{duration(r.started_at, r.finished_at)}</td>
                    <td className="dim"><TimeAgo iso={r.started_at} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {scanId && <ScanProgress key={scanId} scanId={scanId} />}
    </>
  );
}
