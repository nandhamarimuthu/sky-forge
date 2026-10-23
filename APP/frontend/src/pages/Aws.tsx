import { useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, ApiError } from "../api/client";
import { useAwsCost, useAwsResources } from "../api/hooks";
import { Empty, ErrorState, Icon, Kpi, Loading, Sev, SimBanner, Status } from "../components/common";
import { useToast } from "../components/Toast";
import { useFindingDrawer } from "../components/FindingDrawer";
import { PageHead, useSelectedProject } from "../components/PageHead";
import { ProjectPicker } from "../components/ProjectPicker";
import { money } from "../features/agents";

const COLORS = ["#9157FF", "#FF5A5A", "#0EB5A8", "#4361EE", "#FFAE1A", "#F2479A", "#16C47F", "#7D7A99"];
const shortDate = (d: string) => new Date(d).toLocaleDateString("en-GB", { day: "numeric", month: "short" });

interface DumpInfo { name: string; account_id: string; region: string; period_start: string; period_end: string; description: string }

function DataSource({ projectId, source, mode, errors }: { projectId: string; source: any; mode: string; errors: string[] }) {
  const qc = useQueryClient();
  const toast = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const { data: dumps } = useQuery({ queryKey: ["aws-dumps"], queryFn: () => api<DumpInfo[]>("/aws/dumps") });
  const refresh = () => ['aws-cost', 'aws-res'].forEach((k) => qc.invalidateQueries({ queryKey: [k, projectId] }));
  const fail = (e: unknown) => toast(e instanceof ApiError ? e.message : "Request failed", "var(--tomato)");
  const select = async (name: string) => {
    setBusy(true);
    try { await api(`/projects/${projectId}/aws/source`, { method: "PUT", json: { dump: name } }); toast(`Using data dump ${name} — re-scan to refresh findings`, "var(--teal)"); refresh(); }
    catch (e) { fail(e); } finally { setBusy(false); }
  };
  const upload = async (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    setBusy(true);
    try { await api(`/projects/${projectId}/aws/dump`, { method: "POST", body: fd }); toast("Data dump uploaded — re-scan to analyse it", "var(--teal)"); refresh(); }
    catch (e) { fail(e); } finally { setBusy(false); if (fileRef.current) fileRef.current.value = ""; }
  };
  if (mode !== "dump") return null;
  return (
    <div className="card" style={{ padding: 18 }}>
      <div className="row wrap" style={{ gap: 14 }}>
        <div style={{ flex: 1, minWidth: 260 }}>
          <div className="kpi-label">Data source · AWS export</div>
          <div style={{ fontWeight: 700, marginTop: 4 }}>
            {source?.dump ?? "—"} · account <span className="mono">{source?.account_id ?? "?"}</span> · {source?.region ?? "?"} · {source?.period_start} → {source?.period_end}
          </div>
          <div className="muted" style={{ fontSize: ".8rem" }}>{source?.description} {source?.exported_at ? `Exported ${new Date(source.exported_at).toLocaleString()}.` : ""}</div>
          {errors.length > 0 && <div className="error-box" style={{ marginTop: 8 }}>{errors.join("; ")}</div>}
        </div>
        <select className="select input" style={{ width: 220 }} disabled={busy} value="" onChange={(e) => e.target.value && select(e.target.value)} aria-label="Switch data dump">
          <option value="">Switch to bundled dump…</option>
          {(dumps ?? []).map((d) => <option key={d.name} value={d.name}>{d.name} ({d.region})</option>)}
        </select>
        <input ref={fileRef} type="file" accept=".zip" hidden onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => fileRef.current?.click()}><Icon name="download" /> Upload export (.zip)</button>
      </div>
    </div>
  );
}

export function AwsPage() {
  const [project, setProject] = useSelectedProject();
  const cost = useAwsCost(project);
  const res = useAwsResources(project);
  const open = useFindingDrawer();
  const [svc, setSvc] = useState("all");
  const c = cost.data;
  const r = res.data;

  const services = c ? Object.keys(c.by_service) : [];
  const days: Record<string, any> = {};
  if (c) for (const [s, pts] of Object.entries<[string, number][]>(c.by_service)) for (const [d, v] of pts) (days[d] ||= { date: d })[s] = v;
  const series = Object.values(days).sort((a: any, b: any) => a.date.localeCompare(b.date));
  const byRule = c ? Object.entries<number>(c.savings_by_rule).map(([rule, v]) => ({ rule, savings: v })).sort((a, b) => b.savings - a.savings) : [];
  const items = (r?.items ?? []).filter((x: any) => svc === "all" || x.service === svc);

  return (
    <>
      <PageHead eyebrow="AWS optimisation" title="Spend less," highlight="safely"
        sub="Read-only analysis only. Recommendations never change infrastructure; IaC patches go through review and your own Terraform pipeline."
        actions={<ProjectPicker value={project} onChange={setProject} />} />
      {!project ? <div className="card"><Empty title="Select a project" /></div> : cost.error ? <ErrorState error={cost.error} /> : !c ? <Loading rows={4} height={80} /> : (
        <>
          <SimBanner show={c.simulated} />
          <DataSource projectId={project} source={c.source} mode={c.mode} errors={c.errors ?? []} />
          {c.missing_evidence?.length > 0 && <div className="banner info"><b>Missing evidence:</b> {c.missing_evidence.join("; ")}</div>}
          <section className="kpis">
            <Kpi label={c.measured_spend ? "Measured spend · 30d" : "Spend · 30d"} value={money(c.last_30_days)} c="var(--cobalt)" bg="var(--cobalt-t)"
              sub={c.simulated ? <span className="tag tag-sim">simulated</span> : c.measured_spend ? (c.mode === "dump" ? "from Cost & Usage Report" : "Cost Explorer") : "estimated"} />
            <Kpi label="Potential savings / mo" value={money(c.estimated_monthly_savings)} c="var(--mint)" bg="var(--mint-t)"
              sub={<><b>{money(c.estimated_monthly_savings * 12)}</b> per year</>} />
            <Kpi label="Resources" value={r?.items.length ?? "—"} c="var(--teal)" bg="var(--teal-t)" sub={r?.account ? `${r.account.account_id} · ${r.account.regions.join(", ")}` : ""} />
            <Kpi label="Recommendations" value={c.recommendations.length} c="var(--orchid)" bg="var(--orchid-t)"
              sub={<><b>{c.recommendations.filter((x: any) => x.category === "anomaly").length}</b> cost anomalies</>} />
          </section>

          <section className="grid-2-1">
            <div className="card">
              <div className="card-head"><div><h2>Daily cost by service</h2><p className="muted">Last {series.length} days</p></div></div>
              {series.length ? (
                <ResponsiveContainer width="100%" height={260}>
                  <AreaChart data={series}>
                    <CartesianGrid stroke="#ECE8F4" vertical={false} />
                    <XAxis dataKey="date" tickFormatter={shortDate} tick={{ fontSize: 11 }} minTickGap={30} />
                    <YAxis tickFormatter={(v) => `$${v}`} tick={{ fontSize: 11 }} width={56} />
                    <Tooltip formatter={(v: number) => money(v, 2)} labelFormatter={shortDate} />
                    <Legend wrapperStyle={{ fontSize: 12 }} />
                    {services.map((s, i) => <Area key={s} dataKey={s} stackId="1" stroke={COLORS[i % COLORS.length]} fill={COLORS[i % COLORS.length]} fillOpacity={0.35} />)}
                  </AreaChart>
                </ResponsiveContainer>
              ) : <Empty title="Cost data unavailable" />}
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Savings by opportunity</h2><p className="muted">Monthly estimate</p></div></div>
              {byRule.length ? (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={byRule} layout="vertical" margin={{ left: 20 }}>
                    <CartesianGrid stroke="#ECE8F4" horizontal={false} />
                    <XAxis type="number" tickFormatter={(v) => `$${v}`} tick={{ fontSize: 11 }} />
                    <YAxis type="category" dataKey="rule" tick={{ fontSize: 11 }} width={110} />
                    <Tooltip formatter={(v: number) => money(v, 2)} />
                    <Bar dataKey="savings" fill="#16C47F" radius={[0, 6, 6, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <Empty title="No savings found yet">Run a scan with the AWS Cost Optimiser.</Empty>}
            </div>
          </section>

          <div className="card">
            <div className="card-head">
              <div><h2>Read-only recommendations</h2><p className="muted">Evidence, calculation and confidence are in each finding</p></div>
            </div>
            {!c.recommendations.length ? <Empty title="No open recommendations" /> : (
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Recommendation</th><th>Severity</th><th>Savings / mo</th><th>Type</th><th>Confidence</th><th>IaC patch</th></tr></thead>
                  <tbody>
                    {[...c.recommendations].sort((a: any, b: any) => (b.savings ?? 0) - (a.savings ?? 0)).map((x: any) => (
                      <tr key={x.id} className="click" onClick={() => open(x.id)}>
                        <td><b>{x.title}</b></td>
                        <td><Sev s={x.severity} /></td>
                        <td>{x.savings ? <span className="money">{money(x.savings, 2)}</span> : "—"}</td>
                        <td><span className={`tag ${x.savings_type === "hypothetical" ? "tag-est" : "tag-sim"}`}>{x.category === "anomaly" ? "anomaly" : x.savings_type ?? "estimated"}</span></td>
                        <td>{x.confidence}</td>
                        <td>{x.has_iac_patch ? <span className="tag tag-measured">terraform</span> : <span className="dim">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-head"><div><h2>Approved infrastructure changes</h2><p className="muted">Human-approved IaC patches, applied to isolated local branches only</p></div></div>
            {!c.approved_changes.length ? <Empty title="None yet">Approve a Terraform patch from a recommendation to see it here.</Empty> : (
              <table className="table">
                <thead><tr><th>Change</th><th>Status</th><th>Branch</th></tr></thead>
                <tbody>{c.approved_changes.map((a: any) => (
                  <tr key={a.proposal_id} className="click" onClick={() => open(a.finding_id)}>
                    <td><b>{a.title}</b></td><td><Status s={a.status} /></td><td className="mono">{a.branch ?? "—"}</td>
                  </tr>))}
                </tbody>
              </table>
            )}
          </div>

          <div className="card">
            <div className="card-head">
              <div><h2>Resource inventory</h2><p className="muted">{r ? `${r.items.length} resources` : "Loading…"}</p></div>
              <div className="seg">
                {["all", "ec2", "ebs", "rds", "natgateway", "elb", "lambda", "s3", "snapshot"].map((s) => (
                  <button key={s} className={svc === s ? "on" : ""} onClick={() => setSvc(s)}>{s}</button>
                ))}
              </div>
            </div>
            {res.error ? <ErrorState error={res.error} /> : !r ? <Loading /> : (
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Resource</th><th>Service</th><th>Type</th><th>State</th><th>Utilisation (14d avg)</th><th>Cost / mo</th><th>Recommendation</th></tr></thead>
                  <tbody>
                    {items.map((x: any) => {
                      const m = Object.entries<any>(x.metrics)[0];
                      return (
                        <tr key={x.id} className={x.recommendation ? "click" : ""} onClick={() => x.recommendation && open(x.recommendation.finding_id)}>
                          <td><b>{x.name}</b><div className="mono dim" style={{ fontSize: ".72rem" }}>{x.id}{x.iac_address ? ` · ${x.iac_address}` : ""}</div></td>
                          <td><span className="tag tag-ink">{x.service}</span></td>
                          <td className="mono">{x.type}</td>
                          <td>{x.state}</td>
                          <td>{m ? <>{m[0]}: <b>{m[1].avg}</b> {m[1].unit === "Percent" ? "%" : m[1].unit}</> : <span className="dim">—</span>}</td>
                          <td>{money(x.monthly_cost, 2)}</td>
                          <td>{x.recommendation ? <span className="money">{money(x.recommendation.savings, 2)} · {x.recommendation.confidence}</span> : <span className="dim">—</span>}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </>
  );
}
