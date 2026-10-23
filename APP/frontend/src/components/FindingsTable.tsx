import { useState } from "react";
import { useFindings } from "../api/hooks";
import { AGENT_META, AGENT_ORDER, SEVERITIES, label, money } from "../features/agents";
import { AgentTag, DataTag, Empty, ErrorState, Loading, Sev, Status, TimeAgo } from "./common";
import { useFindingDrawer } from "./FindingDrawer";

const STATUSES = ["open", "accepted", "in_progress", "fixed", "verified", "dismissed"];

export function FindingsTable({ fixed = {}, title = "Findings", showProject = true, groupable = true }:
  { fixed?: Record<string, string>; title?: string; showProject?: boolean; groupable?: boolean }) {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState<string[]>([]);
  const [status, setStatus] = useState<string[]>(["open", "accepted", "in_progress"]);
  const [agent, setAgent] = useState("");
  const [sort, setSort] = useState("severity");
  const [group, setGroup] = useState("");
  const [page, setPage] = useState(1);
  const open = useFindingDrawer();
  const params = { ...fixed, q, severity: severity.join(","), status: status.join(","), agent: fixed.agent ?? agent, sort, page, page_size: 25 };
  const { data, isLoading, error, isFetching } = useFindings(params);
  const toggle = (list: string[], set: (v: string[]) => void, v: string) => { set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]); setPage(1); };

  const groups: Record<string, typeof data extends undefined ? never : any[]> = {};
  if (data && group) {
    for (const f of data.items) {
      const k = group === "agent" ? AGENT_META[f.source_agent]?.code ?? f.source_agent : group === "project" ? f.project_name ?? "" : (f as any)[group];
      (groups[k] ||= []).push(f);
    }
  }
  const rows = (items: any[]) =>
    items.map((f) => (
      <tr key={f.id} className="click" onClick={() => open(f.id)}>
        <td><Sev s={f.severity} /></td>
        <td>
          <div style={{ fontWeight: 700 }}>{f.title}</div>
          <div className="svc-meta"><span className="mono">{f.target}{f.location?.line ? `:${f.location.line}` : ""}</span></div>
        </td>
        {showProject && <td>{f.project_name}</td>}
        <td><AgentTag id={f.source_agent} /></td>
        <td><Status s={f.status} /></td>
        <td>{f.estimated_monthly_savings != null ? <span className="money">{money(f.estimated_monthly_savings)}</span> : <DataTag source={f.data_source} />}</td>
        <td>{f.has_proposal ? <span className="tag tag-measured">fix ready</span> : <span className="dim">—</span>}</td>
        <td className="dim"><TimeAgo iso={f.updated_at} /></td>
      </tr>
    ));

  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          <p className="muted">{data ? `${data.total} matching` : " "} {isFetching && !isLoading ? "· refreshing" : ""}</p>
        </div>
        <div className="row wrap">
          <input className="input" style={{ width: 240 }} placeholder="Search title, file, rule, ID…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
          <select className="select input" style={{ width: 150 }} value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort">
            <option value="severity">Sort: severity</option><option value="savings">Sort: savings</option>
            <option value="updated">Sort: updated</option><option value="created">Sort: created</option>
          </select>
          {groupable && (
            <select className="select input" style={{ width: 150 }} value={group} onChange={(e) => setGroup(e.target.value)} aria-label="Group">
              <option value="">No grouping</option><option value="agent">Group: agent</option><option value="category">Group: category</option>
              <option value="status">Group: status</option>{showProject && <option value="project">Group: project</option>}
            </select>
          )}
        </div>
      </div>
      <div className="row wrap" style={{ marginBottom: 10 }}>
        <div className="chips">
          {SEVERITIES.map((s) => (
            <button key={s} className={`chip ${severity.includes(s) ? "on" : ""}`} style={{ ["--c" as any]: s === "critical" || s === "high" ? "var(--tomato)" : s === "medium" ? "var(--sun)" : "var(--teal)" }}
              onClick={() => toggle(severity, setSeverity, s)}>{s} {data?.facets?.severity?.[s] ? `· ${data.facets.severity[s]}` : ""}</button>
          ))}
        </div>
        <span className="spacer" />
        <div className="chips">
          {STATUSES.map((s) => (
            <button key={s} className={`chip ${status.includes(s) ? "on" : ""}`} onClick={() => toggle(status, setStatus, s)}>{label(s)}</button>
          ))}
        </div>
      </div>
      {!fixed.agent && (
        <div className="chips" style={{ marginBottom: 14 }}>
          <button className={`chip ${agent === "" ? "on" : ""}`} onClick={() => setAgent("")}>All agents</button>
          {AGENT_ORDER.map((id) => (
            <button key={id} className={`chip ${agent === id ? "on" : ""}`} style={{ ["--c" as any]: AGENT_META[id].c }} onClick={() => { setAgent(id); setPage(1); }}>
              {AGENT_META[id].code}
            </button>
          ))}
        </div>
      )}
      {isLoading && <Loading rows={6} />}
      {error && <ErrorState error={error} />}
      {data && data.items.length === 0 && <Empty title="No findings match">Adjust the filters or run a scan.</Empty>}
      {data && data.items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>Sev</th><th>Finding</th>{showProject && <th>Project</th>}<th>Agent</th><th>Status</th><th>Impact</th><th>Fix</th><th>Updated</th></tr>
            </thead>
            {group ? Object.entries(groups).map(([k, items]) => (
              <tbody key={k}>
                <tr><td colSpan={8} style={{ background: "var(--bg)", fontWeight: 700 }}>{label(String(k))} <span className="dim">({items.length})</span></td></tr>
                {rows(items)}
              </tbody>
            )) : <tbody>{rows(data.items)}</tbody>}
          </table>
          <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
            <span className="dim" style={{ fontSize: ".82rem" }}>Page {data.page} of {Math.max(1, Math.ceil(data.total / data.page_size))}</span>
            <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
            <button className="btn btn-ghost btn-sm" disabled={page * data.page_size >= data.total} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
