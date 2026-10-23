import { useState } from "react";
import { auth } from "../api/client";

export function LoginPage({ onLogin }: { onLogin: () => Promise<void> }) {
  const [token, setToken] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (token.trim().length < 12) return setErr("Tokens are at least 12 characters.");
    setBusy(true);
    auth.set(token.trim());
    await onLogin();
    setBusy(false);
    if (!auth.get()) setErr("Token rejected by the API.");
  };
  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand" style={{ padding: 0, marginBottom: 20 }}>
          <img className="brand-mark" src="/logo.svg" alt="SkyForge AI logo" />
          <div>
            <div className="brand-name">SkyForge <span>AI</span></div>
            <div className="brand-sub">Cloud &amp; Code Command</div>
          </div>
        </div>
        <h2 style={{ marginBottom: 6 }}>Sign in</h2>
        <p className="muted" style={{ marginBottom: 18 }}>Paste your API access token. It is kept in this browser tab’s session storage only.</p>
        <label className="field">
          <span>Access token</span>
          <input className="input mono" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} autoFocus />
        </label>
        <p className="form-msg err" style={{ marginTop: 10 }}>{err}</p>
        <button className="btn btn-primary" style={{ width: "100%", marginTop: 8 }} disabled={busy}>{busy ? "Checking…" : "Continue"}</button>
        <p className="muted" style={{ fontSize: ".78rem", marginTop: 14 }}>Local dev default: the value of <span className="mono">API_TOKENS</span> in <span className="mono">.env</span>.</p>
      </form>
    </div>
  );
}
