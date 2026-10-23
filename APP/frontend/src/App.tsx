import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api, auth, onUnauthorized } from "./api/client";
import { AppLayout } from "./layouts/AppLayout";
import { AddServicesProvider } from "./components/AddServicesDialog";
import { FindingDrawerProvider } from "./components/FindingDrawer";
import { ToastProvider } from "./components/Toast";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { ProjectsPage } from "./pages/Projects";
import { ProjectDetailPage } from "./pages/ProjectDetail";
import { AgentCenterPage } from "./pages/AgentCenter";
import { SecurityPage } from "./pages/Security";
import { TestingPage } from "./pages/Testing";
import { AwsPage } from "./pages/Aws";
import { CodeHealthPage } from "./pages/CodeHealth";
import { FindingsPage } from "./pages/Findings";
import { SettingsPage } from "./pages/Settings";
import { Empty } from "./components/common";

interface User { name: string; role: string }

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(!!auth.get());
  const qc = useQueryClient();

  const verify = async () => {
    try {
      const s = await api<any>("/settings");
      setUser({ name: s.principal.name, role: s.principal.role });
    } catch {
      auth.clear();
      setUser(null);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    if (auth.get()) verify();
    const off = onUnauthorized(() => { auth.clear(); setUser(null); qc.clear(); });
    return () => { off(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (checking) return <div className="login"><div className="skeleton" style={{ width: 320, height: 120 }} /></div>;
  if (!user) return <LoginPage onLogin={verify} />;

  const logout = () => { auth.clear(); qc.clear(); setUser(null); };
  return (
    <ToastProvider>
      <FindingDrawerProvider>
        <AddServicesProvider>
          <Routes>
            <Route element={<AppLayout user={user} onLogout={logout} />}>
              <Route index element={<OverviewPage />} />
              <Route path="projects" element={<ProjectsPage />} />
              <Route path="projects/:id" element={<ProjectDetailPage />} />
              <Route path="agents" element={<AgentCenterPage />} />
              <Route path="security" element={<SecurityPage />} />
              <Route path="testing" element={<TestingPage />} />
              <Route path="aws" element={<AwsPage />} />
              <Route path="quality" element={<CodeHealthPage />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="*" element={<Empty title="Page not found" />} />
            </Route>
          </Routes>
        </AddServicesProvider>
      </FindingDrawerProvider>
    </ToastProvider>
  );
}
