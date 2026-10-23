import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { Snackbar } from "@mui/material";

interface ToastItem { id: number; msg: string; color?: string }
const Ctx = createContext<(msg: string, color?: string) => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push = useCallback((msg: string, color?: string) => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x, { id, msg, color }]);
    setTimeout(() => setItems((x) => x.filter((t) => t.id !== id)), 4200);
  }, []);
  return (
    <Ctx.Provider value={push}>
      {children}
      <Snackbar open={items.length > 0} anchorOrigin={{ vertical: "bottom", horizontal: "right" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {items.map((t) => (
            <div key={t.id} style={{ background: "#fff", color: "var(--ink)", padding: "12px 16px", borderRadius: 14, fontSize: ".9rem", fontWeight: 600,
              border: "1px solid var(--line)", borderLeft: `6px solid ${t.color ?? "var(--mint)"}`, boxShadow: "var(--shadow-lg)", maxWidth: 380 }}>
              {t.msg}
            </div>
          ))}
        </div>
      </Snackbar>
    </Ctx.Provider>
  );
}

export const useToast = () => useContext(Ctx);
