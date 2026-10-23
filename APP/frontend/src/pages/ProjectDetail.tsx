import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { downloadArtifact } from "../api/client";
import { useArtifacts, useProject, useProjectScans } from "../api/hooks";
import { Empty, ErrorState, Icon, Kpi, Loading, Status, TimeAgo } from "../components/common";
import { FindingsTable } from "../components/FindingsTable";
import { PageHead } from "../components/PageHead";
import { ScanDialog, ScanProgress } from "../components/Scan";
import { useToast } from "../components/Toast";
import { AGENT_META, money } from "../features/agents";
import type { AgentId } from "../types";

export function ProjectDetailPage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const { data: p, error, isLoading } = useProject(id);
  const { data: scans } = useProjectScans(id);
  const [scanOpen, setScanOpen] = useState(false);
  const [tab, setTab] = useState<"findings" | "scans" | "artifacts">("findings");
  const selected = params.get("scan") ?? scans?.items[0]?.id ?? null;
  const { data: artifacts } = useArtifacts(selected);
  const toast = useToast();

  useEffect(() => {
    if (params.get("scan")) setTab("scans");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (error) return <ErrorState error={error} />;
  if (isLoading || !p) return <Loading rows={4} height={80} />;
  const live = p.last_scan && ["queued", "running"].includes(p.last_scan.status);
  const selectScan = (sid: string) => { const n = new URLSearchParams(params); n.set("scan", sid); setParams(n, { replace: true }); };

  return (
    <>
      <PageHead eyebrow="Project" title={p.name}
        sub={<>
          {p.repository && <a href={p.repository.url} target="_blank" rel="noopener noreferrer" className="mono">{p.repository.url.replace("https://", "")}</a>}
          {" "}{p.language} · created by {p.created_by} <TimeAgo iso={p.created_at} />
        </>}
        actions={<>
          <Link to="/projects" className="btn btn-ghost" style={{ display: "inline-flex", alignItems: "center" }}>All projects</Link>
          <button className="btn btn-primary" disabled={!!live} onClick={() => setScanOpen(true)}><Icon name="play" /> {live ? "Scan running…" : "Run scan"}</button>
        </>} />

      <section className="kpis">
        <Kpi label="Open findings" value={p.stats.open_total} c="var(--tomato)" bg="var(--tomato-t)"
          sub={<><b>{(p.stats.open_by_severity.critical ?? 0) + (p.stats.open_by_severity.high ?? 0)}</b> critical/high</>} />
        <Kpi label="Security issues" value={p.stats.vulnerabilities} c="var(--pink)" bg="var(--pink-t)" sub="dependencies, secrets, policy, IaC" />
        <Kpi label="Coverage" value={p.stats.coverage != null ? `${p.stats.coverage}%` : "—"} c="var(--orchid)" bg="var(--orchid-t)"
          sub={p.stats.coverage_before != null ? <>baseline <b>{p.stats.coverage_before}%</b></> : "not measured yet"} />
        <Kpi label="Code health" value={p.stats.health_score ?? "—"} c="#C98F00" bg="var(--sun-t)" sub="0–100 composite" />
        <Kpi label="Savings / mo" value={money(p.stats.estimated_monthly_savings)} c="var(--teal)" bg="var(--teal-t)"
          sub={<>AWS {p.cloud_account?.mode ?? "—"} · {p.cloud_account?.regions.join(", ")}</>} />
      </section>

      <div className="card">
        <div className="card-head">
          <div><h2>Configuration</h2><p className="muted">Repository connection and AWS account reference</p></div>
        </div>
        <dl className="kv">
          <dt>Repository</dt><dd className="mono">{p.repository?.url}</dd>
          <dt>Branch</dt><dd>{p.repository?.branch ?? "default"}</dd>
          <dt>Last commit</dt><dd className="mono">{p.repository?.last_commit?.slice(0, 12) ?? "—"}</dd>
          <dt>Private token</dt><dd>{p.repository?.has_token_ref ? "configured via secret reference" : "none (public repo)"}</dd>
          <dt>AWS account</dt><dd className="mono">{p.cloud_account?.account_id} · tag Project={p.cloud_account?.project_tag}</dd>
          <dt>Scan scope</dt>
          <dd className="row wrap" style={{ gap: 6 }}>{p.scan_scope.map((a) => <span key={a} className="agent-tag" style={{ ["--t" as any]: AGENT_META[a as AgentId]?.t }}>{AGENT_META[a as AgentId]?.name}</span>)}</dd>
        </dl>
      </div>

      <div>
        <div className="tabs">
          {(["findings", "scans", "artifacts"] as const).map((t) => (
            <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>
              {t === "findings" ? "Findings" : t === "scans" ? `Scans (${scans?.total ?? 0})` : "Artifacts"}
            </button>
          ))}
        </div>
        {tab === "findings" && <FindingsTable fixed={{ project_id: p.id }} title="Project findings" showProject={false} />}
        {tab === "scans" && (
          <div className="stack">
            {selected ? <ScanProgress key={selected} scanId={selected} /> : <Empty title="No scans yet" action={<button className="btn btn-primary" onClick={() => setScanOpen(true)}>Run first scan</button>} />}
            {!!scans?.items.length && (
              <div className="card">
                <div className="card-head"><div><h2>Scan history</h2></div></div>
                <div className="table-wrap">
                  <table className="table">
                    <thead><tr><th>Scan</th><th>Status</th><th>Agents</th><th>Findings</th><th>Commit</th><th>Requested</th></tr></thead>
                    <tbody>
                      {scans.items.map((s) => (
                        <tr key={s.id} className="click" onClick={() => selectScan(s.id)} style={s.id === selected ? { background: "var(--orchid-t)" } : undefined}>
                          <td className="mono">{s.id.slice(-8)}</td>
                          <td><Status s={s.status} /></td>
                          <td>{s.agents.length}</td>
                          <td>{s.summary?.findings ?? "—"}</td>
                          <td className="mono">{s.commit_sha?.slice(0, 8) ?? "—"}</td>
                          <td className="dim">{s.requested_by} · <TimeAgo iso={s.created_at} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
        {tab === "artifacts" && (
          <div className="card">
            <div className="card-head"><div><h2>Artifacts</h2><p className="muted">Generated tests, reports, inventories and patches for scan {selected?.slice(-8) ?? "—"}</p></div></div>
            {!artifacts?.length ? <Empty title="No artifacts for this scan" /> : (
              <table className="table">
                <thead><tr><th>Name</th><th>Kind</th><th>Agent</th><th>Size</th><th /></tr></thead>
                <tbody>
                  {artifacts.map((a) => (
                    <tr key={a.id}>
                      <td className="mono">{a.name}</td>
                      <td><span className="tag tag-ink">{a.kind}</span></td>
                      <td>{a.agent_id ? AGENT_META[a.agent_id as AgentId]?.code : "—"}</td>
                      <td>{(a.size / 1024).toFixed(1)} KB</td>
                      <td><button className="btn btn-sm btn-ghost" onClick={() => downloadArtifact(a.scan_id, a.id, a.name).catch(() => toast("Download failed", "var(--tomato)"))}><Icon name="download" /> Download</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
      {scanOpen && <ScanDialog project={p} open onClose={() => setScanOpen(false)} onStarted={(sid) => { selectScan(sid); setTab("scans"); }} />}
    </>
  );
}
