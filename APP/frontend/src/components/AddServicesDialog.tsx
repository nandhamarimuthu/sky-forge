import { createContext, useContext, useState, type ReactNode } from "react";
import { Dialog } from "@mui/material";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { AGENT_META, AGENT_ORDER } from "../features/agents";
import type { AgentId, Project } from "../types";
import { Icon } from "./common";
import { useToast } from "./Toast";

const Ctx = createContext<() => void>(() => undefined);
export const useAddServices = () => useContext(Ctx);

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{1,79}$/;
const URL_RE = /^https:\/\/(www\.)?(github\.com|gitlab\.com|bitbucket\.org)\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}?(\.git)?\/?$/;
const SAMPLES = [
  { name: "Demo Shop", url: "fixture:demo-shop" },
  { name: "Orders API", url: "fixture:orders-api" },
  { name: "Vulnerable Flask App", url: "https://github.com/we45/Vulnerable-Flask-App" },
];

interface Row { name: string; url: string; err?: "name" | "url" }
interface AwsDump { name: string; account_id: string; region: string; period_start: string; period_end: string; project_tag: string; description: string }

export function AddServicesProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <Ctx.Provider value={() => setOpen(true)}>
      {children}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        {open && <AddServicesForm onClose={() => setOpen(false)} />}
      </Dialog>
    </Ctx.Provider>
  );
}

function AddServicesForm({ onClose }: { onClose: () => void }) {
  const [rows, setRows] = useState<Row[]>([{ name: "", url: "" }]);
  const [tag, setTag] = useState("");
  const [dump, setDump] = useState("");
  const { data: dumps } = useQuery({ queryKey: ["aws-dumps"], queryFn: () => api<AwsDump[]>("/aws/dumps") });
  const [branch, setBranch] = useState("");
  const [agents, setAgents] = useState<AgentId[]>([...AGENT_ORDER]);
  const [scanNow, setScanNow] = useState(true);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const qc = useQueryClient();
  const nav = useNavigate();

  const update = (i: number, patch: Partial<Row>) => setRows((r) => r.map((x, j) => (j === i ? { ...x, ...patch, err: undefined } : x)));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const seen = new Set<string>();
    let error = "";
    const checked = rows.map((r) => {
      const name = r.name.trim().replace(/\s+/g, " ");
      const url = r.url.trim();
      if (!name && !url) return r;
      if (!NAME_RE.test(name)) { error ||= `"${name || "(blank)"}" — use 2–80 letters, numbers, spaces, . _ -`; return { ...r, err: "name" as const }; }
      if (seen.has(name.toLowerCase())) { error ||= `Duplicate name "${name}" — names must be unique`; return { ...r, err: "name" as const }; }
      if (!URL_RE.test(url) && !/^fixture:[A-Za-z0-9._-]+$/.test(url)) { error ||= `Not a GitHub/GitLab/Bitbucket https link: ${url || "(blank)"}`; return { ...r, err: "url" as const }; }
      seen.add(name.toLowerCase());
      return { name, url };
    });
    setRows(checked);
    const valid = checked.filter((r) => r.name && r.url && !r.err);
    if (error) return setMsg(error);
    if (!valid.length) return setMsg("Add at least one service.");
    if (!agents.length) return setMsg("Select at least one agent.");
    setBusy(true);
    setMsg("");
    const created: Project[] = [];
    for (const r of valid) {
      try {
        const p = await api<Project>("/projects", {
          method: "POST",
          json: { name: r.name, repo_url: r.url, branch: branch.trim() || null, scan_scope: agents,
            aws: { project_tag: tag.trim() || "", mode: "dump", ...(dump ? { dump } : {}) } },
        });
        created.push(p);
        if (scanNow) await api(`/projects/${p.id}/scans`, { method: "POST", json: {} });
      } catch (err) {
        const m = err instanceof ApiError ? err.message : (err as Error).message;
        setMsg(`${r.name}: ${m}`);
        setRows((rs) => rs.map((x) => (x.name === r.name ? { ...x, err: err instanceof ApiError && err.code === "duplicate_name" ? "name" : "url" } : x)));
        setBusy(false);
        qc.invalidateQueries();
        return;
      }
    }
    setBusy(false);
    qc.invalidateQueries();
    toast(`${created.length} service${created.length > 1 ? "s" : ""} added${scanNow ? " — agents dispatched" : ""}`, "var(--cobalt)");
    onClose();
    if (created.length === 1) nav(`/projects/${created[0].id}`);
    else nav("/projects");
  };

  return (
    <form onSubmit={submit} style={{ padding: 18 }} noValidate>
      <div className="modal-head">
        <img src="/logo.svg" className="modal-logo" alt="" />
        <div>
          <h3 style={{ fontSize: "1.3rem" }}>Add services</h3>
          <p className="muted">Give each service a unique name and its public repository link. Cost analysis uses a one-month AWS data dump.</p>
        </div>
        <button type="button" className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="close" /></button>
      </div>
      <div className="svc-rows-head"><span>Service name</span><span>Repository link</span><span /></div>
      <div className="stack" style={{ gap: 8 }}>
        {rows.map((r, i) => (
          <div className="svc-row" key={i}>
            <input className={`input ${r.err === "name" ? "invalid" : ""}`} placeholder="e.g. Playback Gateway" maxLength={80} value={r.name}
              onChange={(e) => update(i, { name: e.target.value })} aria-label="Service name" />
            <input className={`input mono ${r.err === "url" ? "invalid" : ""}`} placeholder="https://github.com/org/repo" value={r.url}
              onChange={(e) => update(i, { url: e.target.value })} aria-label="Repository link" spellCheck={false} />
            <button type="button" className="icon-btn" disabled={rows.length === 1} onClick={() => setRows((x) => x.filter((_, j) => j !== i))} aria-label="Remove row">
              <Icon name="close" />
            </button>
          </div>
        ))}
      </div>
      <button type="button" className="add-row" onClick={() => setRows((r) => [...r, { name: "", url: "" }])}>+ Add another service</button>
      <div className="form-row" style={{ marginTop: 14 }}>
        <label className="field"><span>AWS cost data (one-month dump)</span>
          <select className="select input" value={dump} onChange={(e) => setDump(e.target.value)}>
            <option value="">Auto — matching sample, else shared-platform</option>
            {(dumps ?? []).map((d) => (
              <option key={d.name} value={d.name}>{d.name} · {d.account_id} · {d.region} · {d.period_start} → {d.period_end}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-row" style={{ marginTop: 14 }}>
        <label className="field"><span>AWS project tag filter (optional)</span>
          <input className="input" maxLength={80} value={tag} onChange={(e) => setTag(e.target.value)} placeholder="defaults to the dump's tag" />
        </label>
        <span />
      </div>
      <div className="form-row" style={{ marginTop: 14 }}>
        <label className="field"><span>Branch (optional)</span>
          <input className="input mono" maxLength={200} value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="default branch" />
        </label>
        <label className="field"><span>After adding</span>
          <label className="toggle on" style={{ ["--c" as any]: "var(--orchid)", ["--t" as any]: "var(--orchid-t)", alignSelf: "flex-start" }}>
            <input type="checkbox" hidden checked={scanNow} onChange={(e) => setScanNow(e.target.checked)} />
            <span className="sw" style={{ background: scanNow ? "var(--orchid)" : "transparent" }} />
            Start a scan immediately
          </label>
        </label>
      </div>
      <div className="field" style={{ marginTop: 14 }}>
        <span>Agents to run</span>
        <div className="chips">
          {AGENT_ORDER.map((id) => {
            const a = AGENT_META[id];
            const on = agents.includes(id);
            return (
              <label key={id} className={`toggle ${on ? "on" : ""}`} style={{ ["--c" as any]: a.c, ["--t" as any]: a.t }}>
                <input type="checkbox" hidden checked={on} onChange={() => setAgents((x) => (on ? x.filter((y) => y !== id) : [...x, id]))} />
                <span className="sw" />
                {a.name}
              </label>
            );
          })}
        </div>
      </div>
      <p className="form-msg err" role="status" style={{ marginTop: 12 }}>{msg}</p>
      <div className="modal-actions">
        <button type="button" className="btn btn-ghost" style={{ marginRight: "auto" }}
          onClick={() => setRows(SAMPLES.map((s) => ({ ...s })))}>Fill sample</button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Adding…" : "Start tracking"}</button>
      </div>
    </form>
  );
}
