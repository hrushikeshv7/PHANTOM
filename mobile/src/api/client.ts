import axios from "axios";
import { CONFIG } from "../config";

// ── Axios instance ────────────────────────────────────────────
export const api = axios.create({
  baseURL: CONFIG.API_BASE_URL,
  headers: {
    "x-api-key":    CONFIG.MOBILE_API_KEY,
    "Content-Type": "application/json",
  },
  timeout: 20000,
});

// ── Types ─────────────────────────────────────────────────────
export interface Threat {
  id:           number;
  ioc:          string;
  ioc_type:     string;
  threat_score: number;
  severity:     string;
  country:      string;
  ai_summary:   string | null;
  created_at:   string;
}

export interface MobileSummary {
  stats: {
    total_analyzed: number;
    critical_count: number;
    high_count:     number;
    medium_count:   number;
    avg_score:      number;
    redis_status:   string;
  };
  recent_threats: Threat[];
  top_threat: {
    ioc:          string;
    threat_score: number;
    severity:     string;
    country:      string;
  } | null;
}

export interface IOCResult {
  threat_score: number;
  severity:     string;
  country?:     string;
  ai_summary?:  string;
  record_id?:   number;
  ioc_type?:    string;
}

export interface Pulse {
  id:          string;
  name:        string;
  description: string;
  created:     string;
  tags:        string[];
  industries:  string[];
}

// ── API calls ─────────────────────────────────────────────────
export const getMobileSummary = async (): Promise<MobileSummary> => {
  const res = await api.get("/api/mobile/summary");
  return res.data;
};

export const getThreats = async (severity?: string): Promise<{ threats: Threat[]; count: number }> => {
  const res = await api.get("/api/mobile/threats", {
    params: { severity, limit: 30 },
  });
  return res.data;
};

export const analyzeIOC = async (
  ioc: string,
  ioc_type: string
): Promise<IOCResult> => {
  const res = await api.get(`/api/analyze/${ioc}`, {
    params: { ioc_type, ai: true },
  });
  return res.data;
};

export const getLiveFeed = async (): Promise<{ pulses: Pulse[]; count: number }> => {
  const res = await api.get("/api/feed", { params: { limit: 20 } });
  return res.data;
};

export const getLeaderboard = async () => {
  const res = await api.get("/api/leaderboard");
  return res.data;
};

export const getStats = async () => {
  const res = await api.get("/api/stats");
  return res.data;
};
