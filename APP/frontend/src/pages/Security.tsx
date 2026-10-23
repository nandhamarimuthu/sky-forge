import { useState } from "react";
import { useFindings } from "../api/hooks";
import { Kpi } from "../components/common";
import { FindingsTable } from "../components/FindingsTable";
import { PageHead } from "../components/PageHead";
import { ProjectPicker } from "../components/ProjectPicker";

const CATEGORIES = [
  { id: "vulnerability", label: "Dependencies", c: "var(--tomato)", bg: "var(--tomato-t)" },
  { id: "secret", label: "Secrets", c: "var(--pink)", bg: "var(--pink-t)" },
  { id: "security_policy", label: "Code & CI policy", c: "var(--orchid)", bg: "var(--orchid-t)" },
  { id: "iac", label: "Infrastructure as code", c: "var(--teal)", bg: "var(--teal-t)" },
];

export function SecurityPage() {
  const [project, setProject] = useState("");
  const [category, setCategory] = useState(CATEGORIES.map((c) => c.id).join(","));
  const all = CATEGORIES.map((c) => c.id).join(",");
  const base = { project_id: project || undefined, status: "open,accepted,in_progress", category: all, page_size: 1 };
  const crit = useFindings({ ...base, severity: "critical" }).data?.total ?? 0;
  const high = useFindings({ ...base, severity: "high" }).data?.total ?? 0;
  const { data } = useFindings(base);
  const facets = data?.facets ?? {};
  const openTotal = data?.total ?? 0;

  return (
    <>
      <PageHead eyebrow="Security" title="Vulnerabilities &" highlight="policy violations"
        sub="Vulnerability Remediation checks dependencies against OSV.dev; Security Guardrails enforces secrets, code, CI and IaC policies. Fixes need human approval."
        actions={<ProjectPicker value={project} onChange={setProject} allowAll />} />
      <section className="kpis">
        <Kpi label="Open security findings" value={openTotal} c="var(--orchid)" bg="var(--orchid-t)" sub="dependencies, secrets, policy, IaC" />
        <Kpi label="Critical" value={crit} c="var(--tomato)" bg="var(--tomato-t)" sub="fix immediately" />
        <Kpi label="High" value={high} c="#E07B00" bg="var(--sun-t)" sub="fix this sprint" />
        <Kpi label="Medium / low" value={Math.max(0, openTotal - crit - high)} c="var(--cobalt)" bg="var(--cobalt-t)" sub="schedule" />
      </section>
      <div className="chips">
        <button className={`chip ${category === all ? "on" : ""}`} onClick={() => setCategory(all)}>All security</button>
        {CATEGORIES.map((c) => (
          <button key={c.id} className={`chip ${category === c.id ? "on" : ""}`} style={{ ["--c" as any]: c.c }} onClick={() => setCategory(c.id)}>
            {c.label} {facets.category?.[c.id] ? `· ${facets.category[c.id]}` : ""}
          </button>
        ))}
      </div>
      <FindingsTable key={category + project} fixed={{ category, ...(project ? { project_id: project } : {}) }} title="Security findings" showProject={!project} />
    </>
  );
}
