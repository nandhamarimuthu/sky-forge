import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, qs } from "./client";
import type { AgentInfo, AgentRun, Artifact, FindingDetail, FindingPage, Page, Project, Proposal, Scan } from "../types";

export const keys = {
  dashboard: ["dashboard"] as const,
  projects: ["projects"] as const,
  project: (id: string) => ["project", id] as const,
  scans: (projectId?: string) => ["scans", projectId ?? "all"] as const,
  scan: (id: string) => ["scan", id] as const,
  findings: (p: Record<string, unknown>) => ["findings", p] as const,
  finding: (id: string) => ["finding", id] as const,
  agents: ["agents"] as const,
};

export const useHealth = () => useQuery({ queryKey: ["health"], queryFn: () => api<any>("/health"), refetchInterval: 30000 });
export const useDashboard = () => useQuery({ queryKey: keys.dashboard, queryFn: () => api<any>("/dashboard/summary"), refetchInterval: 8000 });
export const useProjects = () =>
  useQuery({ queryKey: keys.projects, queryFn: () => api<Page<Project>>("/projects?page_size=100"), refetchInterval: 6000 });
export const useProject = (id?: string) =>
  useQuery({ queryKey: keys.project(id ?? ""), queryFn: () => api<Project>(`/projects/${id}`), enabled: !!id, refetchInterval: 5000 });
export const useProjectScans = (id?: string) =>
  useQuery({ queryKey: keys.scans(id), queryFn: () => api<Page<Scan>>(`/projects/${id}/scans?page_size=30`), enabled: !!id, refetchInterval: 5000 });
export const useScans = () => useQuery({ queryKey: keys.scans(), queryFn: () => api<Page<Scan>>("/scans?page_size=50"), refetchInterval: 4000 });
export const useScan = (id?: string | null) =>
  useQuery({ queryKey: keys.scan(id ?? ""), queryFn: () => api<Scan>(`/scans/${id}`), enabled: !!id, refetchInterval: (q) =>
    q.state.data && ["completed", "partial", "failed", "cancelled"].includes(q.state.data.status) ? false : 2000 });
export const useArtifacts = (scanId?: string | null) =>
  useQuery({ queryKey: ["artifacts", scanId], queryFn: () => api<Artifact[]>(`/scans/${scanId}/artifacts`), enabled: !!scanId });

export const useFindings = (params: Record<string, string | number | undefined>) =>
  useQuery({ queryKey: keys.findings(params), queryFn: () => api<FindingPage>(`/findings${qs(params)}`), placeholderData: (p) => p, refetchInterval: 10000 });
export const useFinding = (id?: string | null) =>
  useQuery({ queryKey: keys.finding(id ?? ""), queryFn: () => api<FindingDetail>(`/findings/${id}`), enabled: !!id,
    refetchInterval: (q) => (q.state.data?.proposals.some((p) => p.status === "applying" || p.verification?.status === "running") ? 1500 : false) });

export const useAgents = () => useQuery({ queryKey: keys.agents, queryFn: () => api<AgentInfo[]>("/agents"), refetchInterval: 5000 });
export const useAgentRuns = (agentId?: string) =>
  useQuery({ queryKey: ["agent-runs", agentId], queryFn: () => api<Page<AgentRun>>(`/agents/${agentId}/runs?page_size=50`), enabled: !!agentId, refetchInterval: 4000 });
export const useTestRuns = (projectId?: string) =>
  useQuery({ queryKey: ["test-runs", projectId ?? "all"], queryFn: () => api<any>(`/test-runs${qs({ project_id: projectId })}`), refetchInterval: 10000 });
export const useAwsCost = (projectId?: string) =>
  useQuery({ queryKey: ["aws-cost", projectId], queryFn: () => api<any>(`/projects/${projectId}/aws/cost`), enabled: !!projectId });
export const useAwsResources = (projectId?: string) =>
  useQuery({ queryKey: ["aws-res", projectId], queryFn: () => api<any>(`/projects/${projectId}/aws/resources`), enabled: !!projectId });
export const useQuality = (projectId?: string) =>
  useQuery({ queryKey: ["quality", projectId], queryFn: () => api<any>(`/projects/${projectId}/quality`), enabled: !!projectId });
export const useSettings = () => useQuery({ queryKey: ["settings"], queryFn: () => api<any>("/settings") });
export const useAudit = (params: Record<string, string | number | undefined>, enabled = true) =>
  useQuery({ queryKey: ["audit", params], queryFn: () => api<any>(`/audit${qs(params)}`), enabled, refetchInterval: 10000 });

export function useInvalidateAll() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries();
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api<Project>("/projects", { method: "POST", json: body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.projects }),
  });
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ projectId, body }: { projectId: string; body: Record<string, unknown> }) =>
      api<Scan>(`/projects/${projectId}/scans`, { method: "POST", json: body }),
    onSuccess: () => qc.invalidateQueries(),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanId: string) => api<Scan>(`/scans/${scanId}/cancel`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries(),
  });
}

export function useReview(findingId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { decision: string; proposal_id?: string; comment?: string }) =>
      api<FindingDetail>(`/findings/${findingId}/review`, { method: "POST", json: body }),
    onSuccess: (data) => {
      qc.setQueryData(keys.finding(findingId), data);
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: keys.dashboard });
    },
  });
}

export function useRemediate(findingId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (proposalId: string) =>
      api<Proposal>(`/findings/${findingId}/remediate`, { method: "POST", json: { proposal_id: proposalId } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.finding(findingId) }),
  });
}

export function useOpenPullRequest(findingId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (proposalId: string) =>
      api<{ url: string; number: number; repo: string; mode: string }>(`/findings/${findingId}/pull-request`,
        { method: "POST", json: { proposal_id: proposalId } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.finding(findingId) }),
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api<any>("/settings", { method: "PUT", json: body }),
    onSuccess: (data) => qc.setQueryData(["settings"], data),
  });
}

export function useResetData() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (confirm: string) =>
      api<{ rows_deleted: number; directories_cleared: string[] }>("/admin/reset", { method: "POST", json: { confirm } }),
    onSuccess: () => { qc.removeQueries(); qc.invalidateQueries(); },
  });
}
