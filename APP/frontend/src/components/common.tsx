import { useEffect, useState, type ReactNode } from "react";
import { ApiError } from "../api/client";
import { AGENT_META, label, normalizeTimestamp, timeAgo } from "../features/agents";
import type { AgentId } from "../types";

// One shared 1s ticker for every relative timestamp on the page.
const tickers = new Set<(n: number) => void>();
let timer: number | undefined;
function useNow(): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    tickers.add(setNow);
    if (timer === undefined) timer = window.setInterval(() => { const n = Date.now(); tickers.forEach((f) => f(n)); }, 1000);
    return () => {
      tickers.delete(setNow);
      if (!tickers.size && timer !== undefined) { window.clearInterval(timer); timer = undefined; }
    };
  }, []);
  return now;
}

export function TimeAgo({ iso }: { iso?: string | null }) {
  const now = useNow();
  const timestamp = iso ? normalizeTimestamp(iso) : undefined;
  return <time dateTime={timestamp} title={timestamp ? new Date(timestamp).toLocaleString() : undefined}>{timeAgo(timestamp, now)}</time>;
}

export function Kpi({ label: l, value, sub, c, bg }: { label: string; value: ReactNode; sub?: ReactNode; c: string; bg: string }) {
  return (
    <div className="kpi" style={{ ["--kc" as any]: c, ["--kbg" as any]: bg }}>
      <div className="kpi-label">{l}</div>
      <div className="kpi-value">{value}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

export const Sev = ({ s }: { s: string }) => <span className={`sev sev-${s}`}>{s}</span>;

export const Status = ({ s, text }: { s: string; text?: string }) => (
  <span className={`status st-${s}`}>
    <i />
    {text ?? label(s)}
  </span>
);

export function DataTag({ source }: { source: string }) {
  const cls = source === "simulated" ? "tag-sim" : source === "measured" ? "tag-measured" : "tag-est";
  return <span className={`tag ${cls}`}>{source}</span>;
}

export function AgentTag({ id }: { id: AgentId }) {
  const a = AGENT_META[id];
  if (!a) return null;
  return (
    <span className="agent-tag" style={{ ["--t" as any]: a.t }}>
      {a.code}
    </span>
  );
}

export function Ring({ value, size = 42 }: { value: number | null | undefined; size?: number }) {
  if (value === null || value === undefined) return <span className="dim">—</span>;
  const rc = value >= 75 ? "var(--mint)" : value >= 55 ? "var(--sun)" : "var(--tomato)";
  return (
    <div className="ring" style={{ ["--p" as any]: value, ["--rc" as any]: rc, width: size, height: size }}>
      <span style={{ width: size - 10, height: size - 10 }}>{Math.round(value)}</span>
    </div>
  );
}

export function Bar({ value, ghost, color }: { value: number; ghost?: number; color?: string }) {
  return (
    <div className="bar" style={{ ["--c" as any]: color }}>
      {ghost !== undefined && <span className="ghost" style={{ width: `${Math.min(100, ghost)}%` }} />}
      <span style={{ width: `${Math.min(100, value)}%` }} />
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action && <div style={{ marginTop: 14 }}>{action}</div>}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const msg = error instanceof ApiError ? `${error.message} (${error.code})` : (error as Error)?.message ?? "Unexpected error";
  return <div className="error-box">Couldn’t load data — {msg}</div>;
}

export function Loading({ rows = 3, height = 46 }: { rows?: number; height?: number }) {
  return (
    <div className="stack" style={{ gap: 10 }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skeleton" style={{ height }} />
      ))}
    </div>
  );
}

export function DiffView({ diff }: { diff: string }) {
  if (!diff.trim()) return <div className="panel dim">No patch — advisory only.</div>;
  return (
    <div className="diff">
      {diff.split("\n").map((l, i) => {
        const cls = l.startsWith("+++") || l.startsWith("---") ? "hdr" : l.startsWith("@@") ? "hunk" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "";
        return (
          <div key={i} className={cls}>
            {l || " "}
          </div>
        );
      })}
    </div>
  );
}

export function SimBanner({ show, children }: { show: boolean; children?: ReactNode }) {
  if (!show) return null;
  return (
    <div className="banner sim">
      <b>Simulated AWS data.</b>
      <span>{children ?? "Inventory, utilisation and spend come from the mock adapter — savings are illustrative estimates, not measured spend."}</span>
    </div>
  );
}

const ICONS: Record<string, ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="9" rx="2" /><rect x="14" y="3" width="7" height="5" rx="2" /><rect x="14" y="12" width="7" height="9" rx="2" /><rect x="3" y="16" width="7" height="5" rx="2" /></>,
  projects: <path d="M4 7h16M4 12h16M4 17h10" />,
  agents: <><rect x="5" y="8" width="14" height="11" rx="3" /><path d="M12 4v4M9 13h.01M15 13h.01" /></>,
  security: <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z" />,
  testing: <><path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3" /></>,
  aws: <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />,
  health: <path d="M3 12h4l3-8 4 16 3-8h4" />,
  findings: <><path d="M9 11l3 3 8-8" /><path d="M20 12v6a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h9" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  play: <path d="M7 4l12 8-12 8z" />,
  stop: <rect x="6" y="6" width="12" height="12" rx="2" />,
  download: <path d="M12 4v12m0 0-5-5m5 5 5-5M4 20h16" />,
  logout: <path d="M15 4h4v16h-4M10 16l-4-4 4-4M6 12h12" />,
  external: <path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6" />,
  "chevron-left": <path d="M15 5l-7 7 7 7" />,
  "chevron-right": <path d="M9 5l7 7-7 7" />,
};

export function Icon({ name }: { name: keyof typeof ICONS | string }) {
  return <svg viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>;
}
