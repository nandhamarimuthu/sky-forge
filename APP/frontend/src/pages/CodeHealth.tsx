import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useQuality } from "../api/hooks";
import { Empty, ErrorState, Kpi, Loading, Ring, Sev, Status } from "../components/common";
import { useFindingDrawer } from "../components/FindingDrawer";
import { PageHead, useSelectedProject } from "../components/PageHead";
import { ProjectPicker } from "../components/ProjectPicker";

export function CodeHealthPage() {
  const [project, setProject] = useSelectedProject();
  const { data, isLoading, error } = useQuality(project);
  const open = useFindingDrawer();
  const m = data?.metrics ?? {};
  const dist = Object.entries<number>(m.complexity_distribution ?? {}).map(([k, v]) => ({ band: k, functions: v })).sort((a, b) => a.band.localeCompare(b.band));
  const lint = Object.entries<number>(m.lint_by_rule ?? {}).map(([rule, n]) => ({ rule, n }));
  const history = (data?.history ?? []).map((h: any, i: number) => ({ ...h, n: i + 1 }));

  return (
    <>
      <PageHead eyebrow="Code health" title="Keep it" highlight="maintainable"
        sub="Ruff, Radon, duplication detection and git churn. Refactors are limited to behaviour-preserving safe fixes and verified after applying."
        actions={<ProjectPicker value={project} onChange={setProject} />} />
      {!project ? <div className="card"><Empty title="Select a project" /></div> : error ? <ErrorState error={error} /> : isLoading ? <Loading rows={4} height={80} /> :
        !data?.scan_id ? <div className="card"><Empty title="No code health analysis yet">Run a scan with the Code Health agent enabled.</Empty></div> : (
        <>
          <section className="kpis">
            <div className="kpi" style={{ ["--kc" as any]: "#C98F00", ["--kbg" as any]: "var(--sun-t)", display: "flex", gap: 14, alignItems: "center" }}>
              <Ring value={m.health_score} size={64} />
              <div><div className="kpi-label">Health score</div><div className="kpi-sub">{m.python_modules} modules · {m.sloc} SLOC</div></div>
            </div>
            <Kpi label="Avg complexity" value={m.avg_complexity ?? "—"} c="var(--orchid)" bg="var(--orchid-t)" sub={<>max <b>{m.max_complexity}</b></>} />
            <Kpi label="Maintainability" value={m.avg_maintainability ?? "—"} c="var(--teal)" bg="var(--teal-t)" sub="Radon MI (higher is better)" />
            <Kpi label="Lint issues" value={m.lint_issues ?? 0} c="var(--tomato)" bg="var(--tomato-t)" sub="Ruff, excluding security rules" />
            <Kpi label="Duplication" value={`${m.duplication_pct ?? 0}%`} c="var(--cobalt)" bg="var(--cobalt-t)" sub={<><b>{m.duplicate_blocks}</b> duplicated blocks</>} />
          </section>

          <section className="grid-3">
            <div className="card">
              <div className="card-head"><div><h2>Health trend</h2></div></div>
              {history.length > 1 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={history}>
                    <CartesianGrid stroke="#ECE8F4" vertical={false} />
                    <XAxis dataKey="n" tick={{ fontSize: 11 }} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} width={30} />
                    <Tooltip labelFormatter={(n) => `Scan #${n}`} />
                    <Line dataKey="health_score" stroke="#FFAE1A" strokeWidth={2.5} />
                  </LineChart>
                </ResponsiveContainer>
              ) : <Empty title="One data point so far">Re-scan to build a trend.</Empty>}
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Complexity distribution</h2></div></div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={dist}>
                  <CartesianGrid stroke="#ECE8F4" vertical={false} />
                  <XAxis dataKey="band" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 11 }} width={34} />
                  <Tooltip />
                  <Bar dataKey="functions" fill="#9157FF" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Top lint rules</h2></div></div>
              {lint.length ? (
                <div className="stack" style={{ gap: 6 }}>
                  {lint.slice(0, 8).map((l) => (
                    <div key={l.rule} className="row">
                      <span className="mono" style={{ width: 70, fontSize: ".8rem" }}>{l.rule}</span>
                      <div className="bar" style={{ flex: 1 }}><span style={{ width: `${(100 * l.n) / lint[0].n}%` }} /></div>
                      <b style={{ width: 30, textAlign: "right" }}>{l.n}</b>
                    </div>
                  ))}
                </div>
              ) : <Empty title="Lint clean" />}
            </div>
          </section>

          <section className="grid-2">
            <div className="card">
              <div className="card-head"><div><h2>Hotspots</h2><p className="muted">Churn × max complexity</p></div></div>
              {!m.hotspots?.length ? <Empty title="No hotspots" /> : (
                <table className="table">
                  <thead><tr><th>File</th><th>Churn</th><th>Max CC</th><th>Score</th></tr></thead>
                  <tbody>{m.hotspots.map((h: any) => (
                    <tr key={h.file}><td className="mono">{h.file}</td><td>{h.churn}</td><td>{h.max_complexity}</td><td><b>{h.score}</b></td></tr>
                  ))}</tbody>
                </table>
              )}
            </div>
            <div className="card">
              <div className="card-head"><div><h2>Refactoring proposals</h2><p className="muted">Before/after metrics appear once verified</p></div></div>
              {!data.refactors.length ? <Empty title="No refactors proposed" /> : (
                <div className="stack" style={{ gap: 10 }}>
                  {data.refactors.map((r: any) => (
                    <div key={r.id} className="panel click" style={{ cursor: "pointer" }} onClick={() => open(r.finding_id)}>
                      <div className="row"><b style={{ flex: 1 }}>{r.title}</b><Status s={r.status} /></div>
                      <div className="muted" style={{ fontSize: ".8rem" }}>{r.summary}</div>
                      {r.verification?.checks && <div className="muted" style={{ fontSize: ".78rem" }}>{r.verification.checks.map((c: any) => `${c.passed ? "✓" : "✗"} ${c.detail}`).join(" · ")}</div>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>

          <div className="card">
            <div className="card-head"><div><h2>Code health findings</h2><p className="muted">{data.findings.length} finding(s) with code references</p></div></div>
            {!data.findings.length ? <Empty title="No findings" /> : (
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Status</th></tr></thead>
                  <tbody>{data.findings.map((f: any) => (
                    <tr key={f.id} className="click" onClick={() => open(f.id)}>
                      <td><Sev s={f.severity} /></td><td><b>{f.title}</b></td>
                      <td className="mono">{f.target}{f.line ? `:${f.line}` : ""}</td><td><Status s={f.status} /></td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </>
  );
}
