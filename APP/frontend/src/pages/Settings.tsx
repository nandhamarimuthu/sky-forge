import { useEffect, useState } from "react";
import { ApiError } from "../api/client";
import { useAudit, useResetData, useSettings, useUpdateSettings } from "../api/hooks";
import { Empty, ErrorState, Loading } from "../components/common";
import { PageHead } from "../components/PageHead";
import { useToast } from "../components/Toast";
import { AGENT_META, AGENT_ORDER } from "../features/agents";

const OUTCOMES = ["", "allowed", "denied", "error", "info"];
const RESET_PHRASE = "DELETE ALL DATA";

function DangerZone() {
  const reset = useResetData();
  const toast = useToast();
  const [phrase, setPhrase] = useState("");
  return (
    <div className="card" style={{ border: "2px solid var(--tomato)" }}>
      <div className="card-head">
        <div>
          <h2>Danger zone</h2>
          <p className="muted">Stops running scans and permanently deletes every project, scan, finding, test run, fix branch,
            artifact and audit event. Settings are kept.</p>
        </div>
      </div>
      <div className="row wrap">
        <input className="input mono" style={{ maxWidth: 260 }} placeholder={`Type ${RESET_PHRASE}`} value={phrase}
          onChange={(e) => setPhrase(e.target.value)} aria-label="Confirmation phrase" />
        <button className="btn btn-sm" style={{ background: "var(--tomato)", color: "#fff" }}
          disabled={phrase !== RESET_PHRASE || reset.isPending}
          onClick={() => reset.mutate(phrase, {
            onSuccess: (r) => { setPhrase(""); toast(`All data cleared (${r.rows_deleted} records)`, "var(--mint)"); },
            onError: (e) => toast(e instanceof ApiError ? e.message : "Reset failed", "var(--tomato)"),
          })}>
          {reset.isPending ? "Clearing…" : "Clear all data"}
        </button>
      </div>
    </div>
  );
}

export function SettingsPage() {
  const { data: s, isLoading, error } = useSettings();
  const update = useUpdateSettings();
  const toast = useToast();
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [outcome, setOutcome] = useState("");
  const [page, setPage] = useState(1);
  const canAudit = !!s?.principal.permissions.includes("audit:read");
  const canWrite = !!s?.principal.permissions.includes("settings:write");
  const audit = useAudit({ outcome: outcome || undefined, page, page_size: 25 }, canAudit);

  useEffect(() => { if (s) setModel(s.llm.model); }, [s]);
  if (error) return <ErrorState error={error} />;
  if (isLoading || !s) return <Loading rows={4} height={90} />;

  const save = (body: Record<string, unknown>, msg: string) =>
    update.mutate(body, {
      onSuccess: () => toast(msg, "var(--mint)"),
      onError: (e) => toast(e instanceof ApiError ? e.message : "Update failed", "var(--tomato)"),
    });
  const policy = s.scan_policy;
  const isOpenAI = s.llm.provider === "openai";

  return (
    <>
      <PageHead eyebrow="Settings & audit" title="Configuration and" highlight="accountability"
        sub={<>Signed in as <b>{s.principal.name}</b> ({s.principal.role}) · permissions: {s.principal.permissions.join(", ")}</>} />

      <section className="grid-2">
        <div className="card">
          <div className="card-head">
            <div><h2>Model provider</h2><p className="muted">{isOpenAI
              ? "OpenAI (gpt-4o-mini) is advisory only — explanations and test drafts leave this machine. Policy enforcement is deterministic."
              : "Ollama runs locally and is advisory only — explanations and test drafts. Policy enforcement is deterministic."}</p></div>
            <span className={`tag ${s.llm.model_available ? "tag-measured" : "tag-sim"}`}>{s.llm.model_available ? "ready" : s.llm.reachable ? "model missing" : isOpenAI && !s.llm.api_key_configured ? "no API key" : "offline"}</span>
          </div>
          <dl className="kv">
            <dt>Endpoint</dt><dd className="mono">{s.llm.base_url}</dd>
            <dt>Available models</dt><dd className="mono" style={{ maxHeight: 60, overflow: "auto" }}>{s.llm.installed_models?.join(", ") || "—"}</dd>
            {isOpenAI && <><dt>API key</dt><dd className="mono">{s.llm.api_key_configured
              ? `${s.llm.api_key_hint} · from ${s.llm.api_key_source === "settings" ? "settings" : s.llm.api_key_env}`
              : `not set — add it below or export ${s.llm.api_key_env}`}</dd></>}
            <dt>CrewAI</dt><dd>{s.llm.crewai_installed ? "installed — crew orchestration enabled" : `not installed — direct ${s.llm.provider} fallback`}</dd>
          </dl>
          <div className="form-row" style={{ marginTop: 14 }}>
            <label className="field"><span>Provider</span>
              <select className="select input" disabled={!canWrite} value={s.llm.provider}
                onChange={(e) => save({ llm_provider: e.target.value }, `Provider switched to ${e.target.value}`)}>
                <option value="ollama">Ollama (local)</option><option value="openai">OpenAI (gpt-4o-mini)</option>
              </select>
            </label>
            <label className="field"><span>LLM assistance</span>
              <select className="select input" disabled={!canWrite} value={String(s.llm.enabled)} onChange={(e) => save({ llm_enabled: e.target.value === "true" }, "LLM setting saved")}>
                <option value="true">Enabled</option><option value="false">Disabled</option>
              </select>
            </label>
          </div>
          <div className="form-row" style={{ marginTop: 14 }}>
            <label className="field"><span>{isOpenAI ? "OpenAI model" : "Ollama model"}</span>
              <input className="input mono" value={model} disabled={!canWrite} onChange={(e) => setModel(e.target.value)} />
            </label>
          </div>
          {isOpenAI && (
            <div className="form-row" style={{ marginTop: 14 }}>
              <label className="field"><span>OpenAI API key</span>
                <input className="input mono" type="password" autoComplete="off" spellCheck={false}
                  placeholder={s.llm.api_key_configured ? "•••••••• (stored)" : "sk-…"}
                  value={apiKey} disabled={!canWrite} onChange={(e) => setApiKey(e.target.value)}
                  aria-label="OpenAI API key" />
              </label>
              {canWrite && (
                <div className="row" style={{ alignItems: "flex-end", gap: 8 }}>
                  <button className="btn btn-sm" disabled={apiKey.trim().length < 20 || update.isPending}
                    onClick={() => { save({ openai_api_key: apiKey.trim() }, "API key saved"); setApiKey(""); }}>Save key</button>
                  <button className="btn btn-sm btn-ghost"
                    disabled={!s.llm.api_key_configured || s.llm.api_key_source !== "settings" || update.isPending}
                    onClick={() => { setApiKey(""); save({ openai_api_key: "" }, "API key cleared"); }}>Clear</button>
                </div>
              )}
            </div>
          )}
          {canWrite && <div className="modal-actions"><button className="btn btn-primary btn-sm" disabled={!/^[A-Za-z0-9._:\-/]+$/.test(model) || update.isPending} onClick={() => save(isOpenAI ? { openai_model: model } : { ollama_model: model }, "Model updated")}>Save model</button></div>}
        </div>

        <div className="card">
          <div className="card-head"><div><h2>Scan policy</h2><p className="muted">Defaults applied to new scans</p></div></div>
          <div className="field"><span>Default agents</span>
            <div className="chips">
              {AGENT_ORDER.map((id) => {
                const on = policy.default_agents.includes(id);
                const a = AGENT_META[id];
                return (
                  <label key={id} className={`toggle ${on ? "on" : ""}`} style={{ ["--c" as any]: a.c, ["--t" as any]: a.t, opacity: canWrite ? 1 : 0.7 }}>
                    <input type="checkbox" hidden disabled={!canWrite} checked={on} onChange={() => {
                      const next = on ? policy.default_agents.filter((x: string) => x !== id) : [...policy.default_agents, id];
                      if (next.length) save({ default_agents: next }, "Default agents saved");
                    }} />
                    <span className="sw" />{a.name}
                  </label>
                );
              })}
            </div>
          </div>
          <div className="form-row" style={{ marginTop: 14 }}>
            <label className="field"><span>Execute tests in sandbox</span>
              <select className="select input" disabled={!canWrite} value={String(policy.execute_tests)} onChange={(e) => save({ execute_tests: e.target.value === "true" }, "Policy saved")}>
                <option value="true">Allowed</option><option value="false">Never execute repository code</option>
              </select>
            </label>
            <label className="field"><span>Generate tests</span>
              <select className="select input" disabled={!canWrite} value={String(policy.auto_generate_tests)} onChange={(e) => save({ auto_generate_tests: e.target.value === "true" }, "Policy saved")}>
                <option value="true">Yes</option><option value="false">No</option>
              </select>
            </label>
          </div>
          <dl className="kv" style={{ marginTop: 14 }}>
            <dt>Agent timeout</dt><dd>{policy.agent_timeout_s}s</dd>
            <dt>Max repo size</dt><dd>{policy.max_repo_mb} MB</dd>
          </dl>
        </div>
      </section>

      <div className="card">
        <div className="card-head"><div><h2>Integrations</h2><p className="muted">Configured server-side; secrets are never returned</p></div></div>
        <dl className="kv">
          <dt>Vulnerability DB</dt><dd className="mono">{s.integrations.osv}</dd>
          <dt>Docker sandbox</dt><dd>{s.integrations.docker_sandbox ? `available · ${s.integrations.sandbox_image}` : "unavailable — test execution refused"}</dd>
          <dt>AWS</dt><dd>Repository Terraform only; dynamically generated cost estimates</dd>
          <dt>AWS regions</dt><dd className="mono">{s.integrations.aws_regions.join(", ")}</dd>
          <dt>AWS services</dt><dd className="mono">{s.integrations.aws_services.join(", ")}</dd>
          <dt>Git hosts</dt><dd className="mono">{s.integrations.git_hosts.join(", ")}</dd>
        </dl>
      </div>

      <div className="card">
        <div className="card-head">
          <div><h2>Audit log</h2><p className="muted">Approvals, tool invocations, remediation outcomes and access denials</p></div>
          {canAudit && (
            <div className="seg">
              {OUTCOMES.map((o) => <button key={o || "all"} className={outcome === o ? "on" : ""} onClick={() => { setOutcome(o); setPage(1); }}>{o || "all"}</button>)}
            </div>
          )}
        </div>
        {!canAudit ? <Empty title="Admin only">Your role cannot read the audit log.</Empty> : audit.error ? <ErrorState error={audit.error} /> : !audit.data ? <Loading /> : !audit.data.items.length ? <Empty title="No events" /> : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th><th>Details</th></tr></thead>
                <tbody>{audit.data.items.map((e: any) => (
                  <tr key={e.id}>
                    <td className="dim" style={{ whiteSpace: "nowrap" }}>{new Date(e.ts).toLocaleString()}</td>
                    <td><b>{e.actor}</b></td>
                    <td className="mono">{e.action}</td>
                    <td className="mono" style={{ fontSize: ".76rem" }}>{e.target_type} {e.target_id}</td>
                    <td><span className={`tag ${e.outcome === "denied" || e.outcome === "error" ? "tag-sim" : "tag-measured"}`}>{e.outcome}</span></td>
                    <td className="mono" style={{ fontSize: ".72rem", maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{JSON.stringify(e.details)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            <div className="row" style={{ justifyContent: "flex-end", marginTop: 12 }}>
              <button className="btn btn-sm btn-ghost" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
              <span className="dim">Page {page} of {Math.max(1, Math.ceil(audit.data.total / 25))}</span>
              <button className="btn btn-sm btn-ghost" disabled={page * 25 >= audit.data.total} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </>
        )}
      </div>

      {canWrite && <DangerZone />}
    </>
  );
}
