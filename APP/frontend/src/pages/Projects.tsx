import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useProjects } from "../api/hooks";
import { Empty, ErrorState, Icon, Loading, Ring, Status, TimeAgo } from "../components/common";
import { PageHead } from "../components/PageHead";
import { useAddServices } from "../components/AddServicesDialog";
import { ScanDialog } from "../components/Scan";
import { hashColor, money } from "../features/agents";
import type { Project } from "../types";

export function ProjectsPage() {
  const { data, isLoading, error } = useProjects();
  const add = useAddServices();
  const nav = useNavigate();
  const [scanFor, setScanFor] = useState<Project | null>(null);
  const items = data?.items ?? [];

  return (
    <>
      <PageHead eyebrow="Projects" title="Tracked" highlight="services"
        sub="Each project links a repository and an AWS account reference. Tokens and secrets are never shown."
        actions={<button className="btn btn-primary" onClick={add}><Icon name="plus" /> Add services</button>} />
      <div className="card">
        <div className="card-head">
          <div><h2>Services</h2><p className="muted">{data ? `${data.total} project(s)` : " "}</p></div>
        </div>
        {error ? <ErrorState error={error} /> : isLoading ? <Loading rows={4} /> : !items.length ? (
          <Empty title="No services yet"
            action={<button className="btn btn-primary" onClick={add}>Add services</button>}>
            Add one or more GitHub repositories to start tracking.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Service</th><th>Last scan</th><th>Health</th><th>Open by severity</th><th>Coverage</th><th>Savings / mo</th><th /></tr>
              </thead>
              <tbody>
                {items.map((p) => {
                  const sev = p.stats.open_by_severity;
                  const live = p.last_scan && ["queued", "running"].includes(p.last_scan.status);
                  return (
                    <tr key={p.id} className="click" onClick={() => nav(`/projects/${p.id}`)}>
                      <td>
                        <div className="svc">
                          <div className="avatar" style={{ background: hashColor(p.name) }}>{p.name[0].toUpperCase()}</div>
                          <div>
                            <div className="svc-name">{p.name}</div>
                            <div className="svc-meta">
                              <span className="mono">{p.repository ? `${p.repository.owner}/${p.repository.name}` : "—"}</span>
                              {p.language !== "auto" && <span>· {p.language}</span>}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td>
                        {p.last_scan ? <Status s={p.last_scan.status} /> : <span className="dim">never</span>}
                        {live && p.last_scan ? (
                          <div className="progress" style={{ width: 120 }}><span style={{ width: `${Math.round(p.last_scan.progress * 100)}%` }} /></div>
                        ) : <div className="muted" style={{ fontSize: ".75rem", marginTop: 2 }}><TimeAgo iso={p.last_scan?.finished_at ?? p.last_scan?.created_at} /></div>}
                      </td>
                      <td><Ring value={p.stats.health_score} /></td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          {(["critical", "high", "medium", "low"] as const).filter((s) => sev[s]).map((s) => (
                            <span key={s} className={`sev sev-${s}`}>{sev[s]} {s[0].toUpperCase()}</span>
                          ))}
                          {!p.stats.open_total && <span className="dim">clean</span>}
                        </div>
                      </td>
                      <td>{p.stats.coverage != null ? <b>{p.stats.coverage}%</b> : <span className="dim">—</span>}
                        {p.stats.coverage_before != null && p.stats.coverage != null && p.stats.coverage > p.stats.coverage_before &&
                          <span style={{ color: "var(--mint)", fontWeight: 700, fontSize: ".8rem" }}> +{(p.stats.coverage - p.stats.coverage_before).toFixed(1)}</span>}
                      </td>
                      <td>{p.stats.estimated_monthly_savings ? <span className="money">{money(p.stats.estimated_monthly_savings)}</span> : <span className="dim">—</span>}</td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <button className="btn btn-sm btn-ghost" disabled={!!live} onClick={() => setScanFor(p)}><Icon name="play" /> Scan</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {scanFor && <ScanDialog project={scanFor} open onClose={() => setScanFor(null)} onStarted={(id) => nav(`/projects/${scanFor.id}?scan=${id}`)} />}
    </>
  );
}
