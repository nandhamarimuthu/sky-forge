import { useProjects } from "../api/hooks";

export function ProjectPicker({ value, onChange, allowAll }: { value?: string; onChange: (id: string) => void; allowAll?: boolean }) {
  const { data } = useProjects();
  return (
    <select className="select input" style={{ width: 260 }} value={value ?? ""} onChange={(e) => onChange(e.target.value)} aria-label="Project">
      {allowAll && <option value="">All projects</option>}
      {!allowAll && !value && <option value="">Select a project…</option>}
      {data?.items.map((p) => (
        <option key={p.id} value={p.id}>{p.name}</option>
      ))}
    </select>
  );
}
