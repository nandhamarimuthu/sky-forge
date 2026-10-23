import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useProjects } from "../api/hooks";

export function PageHead({ eyebrow, title, highlight, sub, actions }:
  { eyebrow: string; title: string; highlight?: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="topbar">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title} {highlight && <span className="hl">{highlight}</span>}</h1>
        {sub && <p className="muted" style={{ marginTop: 6 }}>{sub}</p>}
      </div>
      {actions && <div className="row wrap">{actions}</div>}
    </header>
  );
}

/** Selected project kept in the URL (?project=) and defaulting to the first project. */
export function useSelectedProject(): [string | undefined, (id: string) => void] {
  const [params, setParams] = useSearchParams();
  const { data } = useProjects();
  const fromUrl = params.get("project") ?? undefined;
  const [id, setId] = useState<string | undefined>(fromUrl);
  useEffect(() => {
    if (!id && data?.items.length) setId(data.items[0].id);
  }, [id, data]);
  const set = (v: string) => {
    setId(v);
    const next = new URLSearchParams(params);
    next.set("project", v);
    setParams(next, { replace: true });
  };
  return [id, set];
}
