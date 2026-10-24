import { Link, useNavigate } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useDashboard } from "../api/hooks";
import { AgentTag, Empty, ErrorState, Icon, Kpi, Loading, Ring, Sev, Status, TimeAgo } from "../components/common";
import { useFindingDrawer } from "../components/FindingDrawer";
import { PageHead } from "../components/PageHead";
import { useAddServices } from "../components/AddServicesDialog";
import { AGENT_META, money } from "../features/agents";
import type { AgentId, Scan } from "../types";

const shortDate = (d: string) => new Date(d).toLocaleDateString("en-GB", { day: "numeric", month: "short" });

export function OverviewPage() {
  const { data, isLoading, error } = useDashboard();
  const open = useFindingDrawer();
  const add = useAddServices();
  const nav = useNavigate();
  const today = new Date().toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long" });

  if (error) return <ErrorState error={error} />;
  if (isLoading || !data) return <><PageHead eyebrow={today} title="Loading command centre…" /><Loading rows={5} height={90} /></>;

  const tests = data.tests;
  const passRate = tests.total ? Math.round((100 * tests.passed) / tests.total) : null;
  return (
    <>
      <PageHead eyebrow={today} title="Make every service" highlight="better, safer & cheaper."
        sub="Six specialised agents analyse your repositories and AWS projects; every fix is validated before review."
        actions={<button className="btn btn-primary" onClick={add}><Icon name="plus" /> Add services</button>} />

      {data.projects === 0 ? (
        <div className="card">
          <Empty title="No services onboarded yet" action={<button className="btn btn-primary" onClick={add}>Add your first service</button>}>
            Add a public GitHub repository (or the bundled <span className="mono">fixture:demo-shop</span>) and run a scan.
          </Empty>
        </div>
      ) : (
        <>
          <section className="kpis">
            <Kpi label="Projects monitored" value={data.projects} c="var(--cobalt)" bg="var(--cobalt-t)"
              sub={<><b>{data.recent_scans.filter((s: Scan) => ["queued", "running"].includes(s.status)).length}</b> scans running</>} />
            <Kpi label="Vulnerabilities" value={data.vulnerabilities ?? 0} c="var(--tomato)" bg="var(--tomato-t)"
              sub={<><b>{data.critical_high}</b> Vulnerabilities · <b>{data.open_total}</b> open findings</>} />
            <Kpi label="Unit coverage" value={data.coverage_avg != null ? `${data.coverage_avg}%` : "—"} c="var(--orchid)" bg="var(--orchid-t)"
              sub={passRate != null ? <><b>{tests.passed}/{tests.total}</b> tests passing ({passRate}%)</> : "No measured test runs yet"} />
            <Kpi label="AWS spend · 30d" value={money(data.spend_30d)} c="var(--teal)" bg="var(--teal-t)"
              sub={<><b>{money(data.estimated_monthly_savings)}</b>/mo savings</>} />
            <Kpi label="Code health" value={data.health_avg ?? "—"} c="#C98F00" bg="var(--sun-t)"
              sub={<><b>{data.by_status?.verified ?? 0}</b> fixes verified</>} />
          </section>

          <section className="grid-2-1">
            <div className="card">
              <div className="card-head">
                <div><h2>Cloud spend trend</h2><p className="muted">Daily AWS cost across projects (60 days)</p></div>
              </div>
              {data.spend_series.length ? (
                <ResponsiveContainer width="100%" height={230}>
                  <AreaChart data={data.spend_series}>
                    <defs>
                      <linearGradient id="sp" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#9157FF" stopOpacity={0.35} />
                        <stop offset="100%" stopColor="#FF5A5A" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#ECE8F4" vertical={false} />
                    <XAxis dataKey="date" tickFormatter={shortDate} tick={{ fontSize: 11 }} minTickGap={30} />
                    <YAxis tickFormatter={(v) => `$${v}`} tick={{ fontSize: 11 }} width={56} />
                    <Tooltip formatter={(v: number) => money(v, 2)} labelFormatter={shortDate} />
                    <Area dataKey="cost" stroke="#9157FF" strokeWidth={2} fill="url(#sp)" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : <Empty title="No cost data yet">Run a scan with the AWS Cost Optimiser enabled.</Empty>}
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Risk trend</h2><p className="muted">Critical / high findings per completed scan</p></div></div>
              {data.trend.length ? (
                <ResponsiveContainer width="100%" height={230}>
                  <LineChart data={data.trend.map((t: any, i: number) => ({ ...t, n: i + 1 }))}>
                    <CartesianGrid stroke="#ECE8F4" vertical={false} />
                    <XAxis dataKey="n" tick={{ fontSize: 11 }} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 11 }} width={30} />
                    <Tooltip labelFormatter={(n) => `Scan #${n}`} />
                    <Line dataKey="critical" stroke="#FF5A5A" strokeWidth={2} dot={false} />
                    <Line dataKey="high" stroke="#FFAE1A" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              ) : <Empty title="No completed scans yet" />}
            </div>
          </section>

          <section className="grid-2-1">
            <div className="card">
              <div className="card-head">
                <div><h2>Prioritised actions</h2><p className="muted">Highest risk and savings first — click to review evidence and fixes</p></div>
                <Link to="/findings" className="btn btn-ghost btn-sm" style={{ display: "inline-flex", alignItems: "center" }}>All findings</Link>
              </div>
              {data.top_actions.length ? (
                <ul className="actions">
                  {data.top_actions.map((a: any) => {
                    const m = AGENT_META[a.agent as AgentId];
                    return (
                      <li key={a.id} className="action" style={{ ["--c" as any]: m?.c, ["--t" as any]: m?.t }} onClick={() => open(a.id)}>
                        <span className="stripe" />
                        <div>
                          <div className="action-title">{a.title}</div>
                          <div className="action-meta">
                            <Sev s={a.severity} /><AgentTag id={a.agent} /><span>{a.project}</span>
                            {a.savings ? <span className="money">{money(a.savings)}/mo</span> : null}
                          </div>
                        </div>
                        {a.has_proposal ? <span className="tag tag-measured">fix ready</span> : <span className="dim">review</span>}
                      </li>
                    );
                  })}
                </ul>
              ) : <Empty title="Queue is clear">No open findings — nice.</Empty>}
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Agent activity</h2><p className="muted">Latest run per agent</p></div></div>
              <div className="stack" style={{ gap: 8 }}>
                {data.agent_activity.map((a: any) => {
                  const m = AGENT_META[a.id as AgentId];
                  return (
                    <div key={a.id} className="row panel" style={{ background: m.t, padding: "10px 12px" }}>
                      <span className="agent-num" style={{ ["--c" as any]: m.c, width: 32, height: 32, fontSize: ".8rem", borderRadius: 10 }}>{m.num}</span>
                      <div style={{ flex: 1 }}>
                        <b style={{ fontSize: ".88rem" }}>{a.name}</b>
                        <div className="muted" style={{ fontSize: ".76rem", marginTop: 0 }}>{a.open_findings} open · last run <TimeAgo iso={a.last_run} /></div>
                      </div>
                      {a.running ? <span className="spinner" /> : a.last_status ? <Status s={a.last_status} /> : <span className="dim">idle</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          <section className="grid-2">
            <div className="card">
              <div className="card-head"><div><h2>Services</h2><p className="muted">Posture per project</p></div></div>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Service</th><th>Health</th><th>Coverage</th><th>Open</th><th>Spend 30d</th></tr></thead>
                  <tbody>
                    {data.per_project.map((p: any) => (
                      <tr key={p.id} className="click" onClick={() => nav(`/projects/${p.id}`)}>
                        <td><b>{p.name}</b></td>
                        <td><Ring value={p.health_score} size={38} /></td>
                        <td>{p.coverage != null ? `${p.coverage}%` : <span className="dim">—</span>}</td>
                        <td>{p.open}</td>
                        <td>{money(p.spend_30d)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Recent scans</h2><p className="muted">Live and completed</p></div></div>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Project</th><th>Status</th><th>Findings</th><th>When</th></tr></thead>
                  <tbody>
                    {data.recent_scans.map((s: Scan) => (
                      <tr key={s.id} className="click" onClick={() => nav(`/projects/${s.project_id}?scan=${s.id}`)}>
                        <td><b>{s.project_name}</b></td>
                        <td><Status s={s.status} />{["queued", "running"].includes(s.status) && <div className="progress" style={{ width: 110 }}><span style={{ width: `${Math.round(s.progress * 100)}%` }} /></div>}</td>
                        <td>{s.summary?.findings ?? "—"}</td>
                        <td className="dim"><TimeAgo iso={s.created_at} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        </>
      )}
    </>
  );
}
