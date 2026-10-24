import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useDashboard, useProjects } from "../api/hooks";
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
  const { data: dash } = useDashboard();
  const { data: projects } = useProjects();
  const badges: Record<string, number | undefined> = {
    projects: projects?.total, critical: dash?.critical_high || undefined, open: dash?.open_total || undefined,
  };
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("sf.sidebar") === "collapsed");
  useEffect(() => {
    localStorage.setItem("sf.sidebar", collapsed ? "collapsed" : "expanded");
    document.getElementById("root")?.classList.toggle("rail", collapsed);
  }, [collapsed]);
  return (
    <>
      <aside className={`sidebar${collapsed ? " collapsed" : ""}`}>
        <button
          className="side-toggle"
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!collapsed}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <Icon name={collapsed ? "chevron-right" : "chevron-left"} />
        </button>
        <NavLink to="/" className="brand" title="SkyForge AI">
          <img className="brand-mark" src="/logo.svg" alt="SkyForge AI logo" />
          <div className="brand-text">
            <div className="brand-name">SkyForge <span>AI</span></div>
            <div className="brand-sub">Cloud &amp; Code Command</div>
          </div>
        </NavLink>
        <button className="side-cta" onClick={add} title="Add services"><Icon name="plus" /> <span className="side-cta-label">Add services</span></button>
        <div>
          <div className="side-label">Workspace</div>
          <nav className="nav">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.to === "/"} title={n.label} style={{ ["--c" as any]: n.c, ["--t" as any]: n.t }}>
                <span className="nav-ic"><Icon name={n.icon} /></span>
                <span className="nav-label">{n.label}</span>
                {n.badge && badges[n.badge] ? <span className={`nav-badge ${n.badge === "critical" ? "hot" : ""}`}>{badges[n.badge]}</span> : null}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="side-user">
          <div className="side-avatar" title={`${user.name} · ${user.role}`}>{user.name.slice(0, 2)}</div>
          <div className="side-user-text" style={{ flex: 1 }}>
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
