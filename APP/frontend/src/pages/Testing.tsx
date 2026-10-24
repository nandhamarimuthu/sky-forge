import { Fragment, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { downloadArtifact } from "../api/client";
import { useTestRuns } from "../api/hooks";
import { AgentTag, Empty, ErrorState, Icon, Kpi, Loading, Sev, Status, TimeAgo } from "../components/common";
import { useFindingDrawer } from "../components/FindingDrawer";
import { PageHead } from "../components/PageHead";
import { ProjectPicker } from "../components/ProjectPicker";
import { useToast } from "../components/Toast";
import { formatDuration } from "../features/agents";
import type { TestRun } from "../types";

export function TestingPage() {
  const [project, setProject] = useState("");
  const { data, isLoading, error } = useTestRuns(project || undefined);
  const [expanded, setExpanded] = useState<string | null>(null);
  const open = useFindingDrawer();
  const toast = useToast();

  const runs: TestRun[] = data?.runs ?? [];
  const latestUnit = runs.find((r) => r.kind === "unit" && r.coverage_after != null);
  const executed = runs.filter((r) => r.status !== "not_executed");
  const passed = executed.reduce((a, r) => a + r.passed, 0);
  const total = executed.reduce((a, r) => a + r.total, 0);
  const generated = (data?.coverage_history ?? []).reduce((a: number, h: any) => a + (h.generated || 0), 0);
  const history = (data?.coverage_history ?? []).map((h: any, i: number) => ({
    name: `${h.project ?? ""} #${i + 1}`, Baseline: h.before ?? 0, "With generated tests": h.after ?? h.before ?? 0,
  }));

  return (
    <>
      <PageHead eyebrow="Testing" title="Coverage &" highlight="functional journeys"
        sub="Tests run inside an isolated Docker sandbox (no network during execution). Only generated tests that pass are proposed."
        actions={<ProjectPicker value={project} onChange={setProject} allowAll />} />
      {error ? <ErrorState error={error} /> : isLoading ? <Loading rows={4} height={70} /> : (
        <>
          <section className="kpis">
            <Kpi label="Latest coverage" value={latestUnit ? `${latestUnit.coverage_after}%` : "—"} c="var(--orchid)" bg="var(--orchid-t)"
              sub={latestUnit?.coverage_before != null ? <>baseline <b>{latestUnit.coverage_before}%</b></> : "measured in sandbox"} />
            <Kpi label="Tests passing" value={total ? `${passed}/${total}` : "—"} c="var(--mint)" bg="var(--mint-t)" sub={`${executed.length} executed run(s)`} />
            <Kpi label="Tests generated" value={generated} c="var(--cobalt)" bg="var(--cobalt-t)" sub="validated before proposal" />
            <Kpi label="Coverage gaps" value={data?.gaps.length ?? 0} c="var(--tomato)" bg="var(--tomato-t)" sub="modules & journeys" />
          </section>

          <section className="grid-2-1">
            <div className="card">
              <div className="card-head"><div><h2>Coverage history</h2><p className="muted">Baseline vs. with SkyForge-generated tests, per scan</p></div></div>
              {history.length ? (
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={history}>
                    <CartesianGrid stroke="#ECE8F4" vertical={false} />
                    <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                    <YAxis domain={[0, 100]} tickFormatter={(v) => `${v}%`} tick={{ fontSize: 11 }} width={44} />
                    <Tooltip formatter={(v: number) => `${v}%`} />
                    <Legend />
                    <Bar dataKey="Baseline" fill="#C9C2EC" radius={[6, 6, 0, 0]} />
                    <Bar dataKey="With generated tests" fill="#4361EE" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <Empty title="No coverage measured yet">Run a scan with Unit Test & Coverage and the Docker sandbox enabled.</Empty>}
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Missing coverage</h2><p className="muted">Open gaps with proposed tests</p></div></div>
              {!data?.gaps.length ? <Empty title="No open gaps" /> : (
                <ul className="actions">
                  {data.gaps.slice(0, 12).map((g: any) => (
                    <li key={g.id} className="action" style={{ ["--c" as any]: g.category === "functional" ? "var(--orchid)" : "var(--cobalt)" }} onClick={() => open(g.id)}>
                      <span className="stripe" />
                      <div>
                        <div className="action-title" style={{ fontSize: ".86rem" }}>{g.title}</div>
                        <div className="action-meta"><Sev s={g.severity} /><span>{g.project}</span></div>
                      </div>
                      {g.has_proposal ? <span className="tag tag-measured">tests ready</span> : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          <div className="card">
            <div className="card-head"><div><h2>Test executions</h2><p className="muted">Unit, functional and post-fix verification runs</p></div></div>
            {!runs.length ? <Empty title="No test runs yet" /> : (
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Project</th><th>Kind</th><th>Agent</th><th>Status</th><th>Results</th><th>Coverage</th><th>Duration</th><th>When</th><th /></tr></thead>
                  <tbody>
                    {runs.map((r) => (
                      <Fragment key={r.id}>
                        <tr className="click" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                          <td><b>{r.project_name}</b><div className="muted" style={{ fontSize: ".74rem" }}>{r.details?.label}</div></td>
                          <td><span className="tag tag-ink">{r.kind}</span></td>
                          <td><AgentTag id={r.agent_id as any} /></td>
                          <td><Status s={r.status} /></td>
                          <td>{r.status === "not_executed" ? <span className="dim">{r.details?.reason ?? "not executed"}</span> :
                            <><b style={{ color: "#0B8A5E" }}>{r.passed}</b> / {r.total}{r.failed + r.errors > 0 && <span style={{ color: "var(--tomato)" }}> · {r.failed + r.errors} failing</span>}</>}</td>
                          <td>{r.coverage_after != null ? <>{r.coverage_before != null && <span className="dim">{r.coverage_before}% → </span>}<b>{r.coverage_after}%</b></> : "—"}</td>
                          <td>{formatDuration(r.duration_s)}</td>
                          <td className="dim"><TimeAgo iso={r.created_at} /></td>
                          <td onClick={(e) => e.stopPropagation()}>
                            {r.report_artifact_id && (
                              <button className="icon-btn" title="Download report" onClick={() => downloadArtifact(r.scan_id, r.report_artifact_id!, `${r.kind}-report.log`).catch(() => toast("Download failed", "var(--tomato)"))}>
                                <Icon name="download" />
                              </button>
                            )}
                          </td>
                        </tr>
                        {expanded === r.id && (
                          <tr>
                            <td colSpan={9}>
                              {r.details?.failures?.length ? (
                                <div className="stack" style={{ gap: 6 }}>
                                  {r.details.failures.map((f: any, i: number) => (
                                    <div key={i} className="panel" style={{ background: "var(--tomato-t)" }}>
                                      <b className="mono" style={{ fontSize: ".8rem" }}>{f.test}</b>
                                      <div className="muted" style={{ fontSize: ".78rem" }}>{f.message}</div>
                                    </div>
                                  ))}
                                </div>
                              ) : <span className="dim">{r.details?.reason || "No failures recorded."}</span>}
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
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
