import { create } from "zustand";
import { Threat, MobileSummary } from "../api/client";

interface PhantomStore {
  // Data
  summary:       MobileSummary | null;
  threats:       Threat[];
  wsConnected:   boolean;
  lastWsEvent:   any | null;

  // Setters
  setSummary:     (s: MobileSummary) => void;
  setThreats:     (t: Threat[]) => void;
  setWsConnected: (v: boolean) => void;
  addWsEvent:     (e: any) => void;
  addLiveThreat:  (t: Threat) => void;
}

export const usePhantomStore = create<PhantomStore>((set) => ({
  summary:      null,
  threats:      [],
  wsConnected:  false,
  lastWsEvent:  null,

  setSummary:     (summary)     => set({ summary }),
  setThreats:     (threats)     => set({ threats }),
  setWsConnected: (wsConnected) => set({ wsConnected }),
  addWsEvent:     (lastWsEvent) => set({ lastWsEvent }),

  // Prepend live threats from WebSocket to the top of the list
  addLiveThreat: (threat) =>
    set((state) => ({
      threats: [threat, ...state.threats].slice(0, 50),
      summary: state.summary
        ? {
            ...state.summary,
            recent_threats: [threat, ...state.summary.recent_threats].slice(0, 10),
            stats: {
              ...state.summary.stats,
              total_analyzed: state.summary.stats.total_analyzed + 1,
              critical_count:
                threat.severity === "CRITICAL"
                  ? state.summary.stats.critical_count + 1
                  : state.summary.stats.critical_count,
            },
          }
        : null,
    })),
}));
