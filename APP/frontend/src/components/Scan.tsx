import { useEffect, useRef, useState } from "react";
import { Dialog } from "@mui/material";
import { useCancelScan, useScan, useStartScan } from "../api/hooks";
import { ApiError } from "../api/client";
import { AGENT_META, AGENT_ORDER, label } from "../features/agents";
import { useScanEvents } from "../hooks/useScanEvents";
import type { AgentId, Project } from "../types";
import { Icon, Status, TimeAgo } from "./common";
import { useToast } from "./Toast";

export function ScanDialog({ project, open, onClose, onStarted }: { project: Project; open: boolean; onClose: () => void; onStarted?: (id: string) => void }) {
  const [agents, setAgents] = useState<AgentId[]>(project.scan_scope);
  const [opts, setOpts] = useState({ execute_tests: true, generate_tests: true, use_llm: true });
  const start = useStartScan();
  const toast = useToast();
  const [err, setErr] = useState("");
  const toggle = (k: keyof typeof opts) => setOpts((o) => ({ ...o, [k]: !o[k] }));
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <div style={{ padding: 18 }}>
        <div className="modal-head">
          <img src="/logo.svg" className="modal-logo" alt="" />
          <div>
            <h3 style={{ fontSize: "1.25rem" }}>Run scan · {project.name}</h3>
            <p className="muted">Agents run concurrently with timeouts; generated code is validated by guardrails before review.</p>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="close" /></button>
        </div>
        <div className="field">
          <span>Agents</span>
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
        <div className="field" style={{ marginTop: 14 }}>
          <span>Options</span>
          <div className="chips">
            {([["execute_tests", "Execute tests in Docker sandbox"], ["generate_tests", "Generate tests"], ["use_llm", "Use local LLM (Ollama)"]] as const).map(([k, l]) => (
              <label key={k} className={`toggle ${opts[k] ? "on" : ""}`} style={{ ["--c" as any]: "var(--orchid)", ["--t" as any]: "var(--orchid-t)" }}>
                <input type="checkbox" hidden checked={opts[k]} onChange={() => toggle(k)} />
                <span className="sw" />
                {l}
              </label>
            ))}
          </div>
        </div>
        <p className="form-msg err" style={{ marginTop: 10 }}>{err}</p>
        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={!agents.length || start.isPending}
            onClick={() => start.mutate({ projectId: project.id, body: { agents, options: opts } }, {
              onSuccess: (s) => { toast("Scan queued — streaming progress", "var(--cobalt)"); onStarted?.(s.id); onClose(); },
              onError: (e) => setErr(e instanceof ApiError ? e.message : (e as Error).message),
            })}>
            <Icon name="play" /> Start scan
          </button>
        </div>
      </div>
    </Dialog>
  );
}

export function ScanProgress({ scanId }: { scanId: string }) {
  const { data: scan } = useScan(scanId);
  const stream = useScanEvents(scanId);
  const cancel = useCancelScan();
  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [stream.events.length]);
  if (!scan) return null;
  const live = ["queued", "running"].includes(scan.status);
  const progress = Math.round(100 * Math.max(scan.progress, stream.progress || 0));
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <div className="row">
            <h2>Scan {scan.id.slice(-8)}</h2>
            <Status s={stream.status ?? scan.status} />
            {stream.connected && <span className="tag tag-measured">live</span>}
          </div>
          <p className="muted">
            Requested by {scan.requested_by} · <TimeAgo iso={scan.created_at} />
            {scan.commit_sha && <> · commit <span className="mono">{scan.commit_sha.slice(0, 10)}</span></>}
          </p>
        </div>
        {live && (
          <button className="btn btn-danger btn-sm" disabled={cancel.isPending} onClick={() => cancel.mutate(scan.id)}>
            <Icon name="stop" /> Cancel scan
          </button>
        )}
      </div>
      <div className="progress" style={{ marginBottom: 16 }}><span style={{ width: `${live ? progress : 100}%` }} /></div>
      {scan.error && <div className="error-box" style={{ marginBottom: 14 }}>{scan.error}</div>}
      <div className="grid-3" style={{ marginBottom: 16 }}>
        {scan.agent_runs.map((r) => {
          const a = AGENT_META[r.agent_id];
          return (
            <div key={r.id} className="panel" style={{ background: a.t }}>
              <div className="row" style={{ marginBottom: 6 }}>
                <b style={{ flex: 1, fontSize: ".86rem" }}>{a.name}</b>
                {r.status === "running" ? <span className="spinner" /> : <Status s={r.status} />}
              </div>
              <div className="progress" style={{ background: "#fff" }}><span style={{ width: `${Math.round(r.progress * 100)}%` }} /></div>
              <div className="muted" style={{ fontSize: ".76rem" }}>
                {r.findings_count} findings{r.attempts > 1 ? ` · ${r.attempts} attempts` : ""}{r.error ? ` · ${r.error.slice(0, 80)}` : ""}
              </div>
            </div>
          );
        })}
      </div>
      <div className="log" ref={logRef} aria-live="polite">
        {stream.events.length === 0 && <div className="dim">Waiting for events…</div>}
        {stream.events.map((e) => (
          <div key={e.id} className={e.level}>
            <span className="dim">{new Date(e.ts).toLocaleTimeString()} </span>
            {e.agent_id && <span className="ag">[{AGENT_META[e.agent_id]?.short ?? e.agent_id}] </span>}
            {e.message || label(e.type)}
          </div>
        ))}
      </div>
    </div>
  );
}
