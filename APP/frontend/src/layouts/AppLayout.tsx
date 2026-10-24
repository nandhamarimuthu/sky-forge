import { NavLink, Outlet } from "react-router-dom";
import { useDashboard, useHealth, useProjects } from "../api/hooks";
import { Icon } from "../components/common";
import { useAddServices } from "../components/AddServicesDialog";

const NAV = [
  { to: "/", label: "Overview", icon: "overview", c: "var(--cobalt)", t: "var(--cobalt-t)" },
  { to: "/projects", label: "Projects", icon: "projects", c: "var(--teal)", t: "var(--teal-t)", badge: "projects" },
  { to: "/agents", label: "Agent Center", icon: "agents", c: "var(--orchid)", t: "var(--orchid-t)" },
  { to: "/security", label: "Security", icon: "security", c: "var(--tomato)", t: "var(--tomato-t)", badge: "critical" },
  { to: "/testing", label: "Testing", icon: "testing", c: "var(--cobalt)", t: "var(--cobalt-t)" },
  { to: "/aws", label: "AWS Optimization", icon: "aws", c: "var(--teal)", t: "var(--teal-t)" },
  { to: "/quality", label: "Code Health", icon: "health", c: "var(--sun)", t: "var(--sun-t)" },
  { to: "/findings", label: "Findings", icon: "findings", c: "var(--pink)", t: "var(--pink-t)", badge: "open" },
  { to: "/settings", label: "Settings & Audit", icon: "settings", c: "var(--ink-2)", t: "var(--line)" },
];

export function AppLayout({ user, onLogout }: { user: { name: string; role: string }; onLogout: () => void }) {
  const add = useAddServices();
  const { data: health } = useHealth();
  const { data: dash } = useDashboard();
  const { data: projects } = useProjects();
  const badges: Record<string, number | undefined> = {
    projects: projects?.total, critical: dash?.critical_high || undefined, open: dash?.open_total || undefined,
  };
  return (
    <>
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          <img className="brand-mark" src="/logo.svg" alt="SkyForge AI logo" />
          <div>
            <div className="brand-name">SkyForge <span>AI</span></div>
            <div className="brand-sub">Cloud &amp; Code Command</div>
          </div>
        </NavLink>
        <button className="side-cta" onClick={add}><Icon name="plus" /> Add services</button>
        <div>
          <div className="side-label">Workspace</div>
          <nav className="nav">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.to === "/"} style={{ ["--c" as any]: n.c, ["--t" as any]: n.t }}>
                <span className="nav-ic"><Icon name={n.icon} /></span>
                {n.label}
                {n.badge && badges[n.badge] ? <span className={`nav-badge ${n.badge === "critical" ? "hot" : ""}`}>{badges[n.badge]}</span> : null}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="side-card">
          <div className="side-card-title">Runtime</div>
          <div className="side-row">
            <span className={`pulse ${health?.llm?.model_available ? "" : health?.llm?.reachable ? "warn" : "off"}`} />
            {health?.llm?.provider === "openai" ? "OpenAI" : "Ollama"} · {health?.llm?.model ?? "…"} {!health?.llm?.reachable && <em style={{ color: "#A86A00", background: "var(--sun-t)" }}>offline</em>}
          </div>
          <div className="side-row"><span className={`pulse ${health?.sandbox ? "" : "off"}`} />Docker sandbox {!health?.sandbox && <em style={{ color: "#A86A00", background: "var(--sun-t)" }}>off</em>}</div>
          <div className="side-row"><span className="pulse" />AWS · <em>{health?.aws_mode === "live" ? "read-only" : "data dump"}</em></div>
        </div>
        <div className="side-user">
          <div className="side-avatar">{user.name.slice(0, 2)}</div>
          <div style={{ flex: 1 }}>
            <div className="side-user-name">{user.name}</div>
            <div className="side-user-role">{user.role}</div>
          </div>
          <button className="icon-btn" onClick={onLogout} aria-label="Sign out" title="Sign out"><Icon name="logout" /></button>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </>
  );
}
