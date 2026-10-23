import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { auth } from "../api/client";
import type { ScanEvent } from "../types";

interface StreamState {
  events: ScanEvent[];
  status: string | null;
  progress: number;
  connected: boolean;
  error: string | null;
}

/**
 * Server-Sent Events over fetch (so the bearer token travels in a header, never in the URL).
 * Reconnects with the last event id after transient failures.
 */
export function useScanEvents(scanId: string | null | undefined): StreamState {
  const [state, setState] = useState<StreamState>({ events: [], status: null, progress: 0, connected: false, error: null });
  const lastId = useRef(0);
  const qc = useQueryClient();

  useEffect(() => {
    if (!scanId) return;
    lastId.current = 0;
    setState({ events: [], status: null, progress: 0, connected: false, error: null });
    const ctrl = new AbortController();
    let stopped = false;

    const run = async (attempt: number): Promise<void> => {
      try {
        const res = await fetch(`/api/v1/scans/${encodeURIComponent(scanId)}/events?after=${lastId.current}`, {
          headers: { Authorization: `Bearer ${auth.get() ?? ""}`, Accept: "text/event-stream" },
          signal: ctrl.signal,
        });
        if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
        setState((s) => ({ ...s, connected: true, error: null }));
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let idx: number;
          while ((idx = buffer.indexOf("\n\n")) >= 0) {
            const chunk = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            let event = "message";
            let data = "";
            for (const line of chunk.split("\n")) {
              if (line.startsWith("event:")) event = line.slice(6).trim();
              else if (line.startsWith("data:")) data += line.slice(5).trim();
            }
            if (!data) continue;
            if (event === "end") {
              stopped = true;
              qc.invalidateQueries();
              setState((s) => ({ ...s, connected: false }));
              return;
            }
            const parsed = JSON.parse(data);
            if (event === "snapshot") {
              setState((s) => ({ ...s, status: parsed.status, progress: parsed.progress }));
            } else {
              lastId.current = Math.max(lastId.current, parsed.id);
              setState((s) => ({ ...s, events: [...s.events, parsed as ScanEvent].slice(-600) }));
              if (event === "agent.status" || event === "scan.status") qc.invalidateQueries({ queryKey: ["scan", scanId] });
            }
          }
        }
      } catch (e) {
        if (ctrl.signal.aborted) return;
        setState((s) => ({ ...s, connected: false, error: (e as Error).message }));
      }
      if (!stopped && !ctrl.signal.aborted && attempt < 20) {
        await new Promise((r) => setTimeout(r, Math.min(1000 * 2 ** attempt, 8000)));
        return run(attempt + 1);
      }
    };
    run(0);
    return () => ctrl.abort();
  }, [scanId, qc]);

  return state;
}
