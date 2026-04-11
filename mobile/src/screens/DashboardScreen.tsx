import React, { useEffect, useCallback } from "react";
import {
  View, Text, ScrollView, StyleSheet,
  RefreshControl, ActivityIndicator, TouchableOpacity,
} from "react-native";
import { getMobileSummary } from "../api/client";
import { usePhantomStore } from "../store/usePhantomStore";
import { StatCard } from "../components/StatCard";
import { ThreatCard } from "../components/ThreatCard";
import { THEME, CONFIG } from "../config";

export const DashboardScreen = () => {
  const { summary, setSummary, wsConnected, setWsConnected, addLiveThreat, addWsEvent } =
    usePhantomStore();
  const [loading,    setLoading]    = React.useState(true);
  const [refreshing, setRefreshing] = React.useState(false);
  const [error,      setError]      = React.useState<string | null>(null);
  const wsRef = React.useRef<WebSocket | null>(null);

  // ── Fetch summary ─────────────────────────────────────────
  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const data = await getMobileSummary();
      setSummary(data);
    } catch (e: any) {
      setError("Backend unreachable. Is PHANTØM running on Render?");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  // ── WebSocket live feed ───────────────────────────────────
  const connectWs = useCallback(() => {
    try {
      const ws = new WebSocket(CONFIG.WS_URL);

      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => {
        setWsConnected(false);
        // Reconnect after 5 seconds
        setTimeout(connectWs, 5000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          addWsEvent(data);
          if (data.type === "new_threat") {
            addLiveThreat({
              id:           Date.now(),
              ioc:          data.ioc,
              ioc_type:     "ip",
              threat_score: data.threat_score,
              severity:     data.severity,
              country:      data.country ?? "Unknown",
              ai_summary:   data.ai_summary,
              created_at:   new Date().toISOString(),
            });
          }
        } catch (_) {}
      };

      wsRef.current = ws;
    } catch (_) {}
  }, []);

  useEffect(() => {
    fetchData();
    connectWs();
    return () => wsRef.current?.close();
  }, []);

  if (loading) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator size="large" color={THEME.accent} />
        <Text style={styles.loadingText}>CONNECTING TO PHANTØM...</Text>
      </View>
    );
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl
          refreshing={refreshing}
          onRefresh={() => { setRefreshing(true); fetchData(); }}
          tintColor={THEME.accent}
        />
      }
    >
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.logo}>PHANTØM</Text>
        <View style={styles.wsIndicator}>
          <View style={[styles.dot, { backgroundColor: wsConnected ? THEME.green : THEME.red }]} />
          <Text style={styles.wsText}>{wsConnected ? "LIVE" : "OFFLINE"}</Text>
        </View>
      </View>

      <Text style={styles.subtitle}>SOC THREAT INTELLIGENCE</Text>

      {error && (
        <View style={styles.errorBox}>
          <Text style={styles.errorText}>{error}</Text>
        </View>
      )}

      {summary && (
        <>
          {/* Stats Grid */}
          <Text style={styles.sectionLabel}>PLATFORM STATS</Text>
          <View style={styles.statsRow}>
            <StatCard
              label="Total Analyzed"
              value={summary.stats.total_analyzed}
              color={THEME.accent}
            />
            <StatCard
              label="Critical"
              value={summary.stats.critical_count}
              color={THEME.red}
            />
          </View>
          <View style={styles.statsRow}>
            <StatCard
              label="High"
              value={summary.stats.high_count}
              color={THEME.orange}
            />
            <StatCard
              label="Avg Score"
              value={summary.stats.avg_score}
              color={THEME.yellow}
            />
          </View>

          {/* Top Threat */}
          {summary.top_threat && (
            <>
              <Text style={styles.sectionLabel}>TOP THREAT</Text>
              <View style={styles.topThreat}>
                <Text style={styles.topIoc}>{summary.top_threat.ioc}</Text>
                <Text style={[styles.topScore, { color: THEME.red }]}>
                  {summary.top_threat.threat_score.toFixed(1)}
                </Text>
                <Text style={styles.topMeta}>
                  {summary.top_threat.severity} · {summary.top_threat.country}
                </Text>
              </View>
            </>
          )}

          {/* Recent Threats */}
          <Text style={styles.sectionLabel}>
            RECENT THREATS
            <Text style={styles.sectionCount}> ({summary.recent_threats.length})</Text>
          </Text>
          {summary.recent_threats.map((t) => (
            <ThreatCard key={t.id} threat={t} />
          ))}
        </>
      )}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: THEME.bg },
  content:   { padding: 16, paddingBottom: 32 },
  centered:  { flex: 1, backgroundColor: THEME.bg, justifyContent: "center", alignItems: "center" },
  loadingText: { color: THEME.accent, marginTop: 12, fontSize: 11, letterSpacing: 2 },

  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 4 },
  logo:   { color: THEME.accent, fontSize: 28, fontWeight: "900", letterSpacing: 4 },
  subtitle: { color: THEME.textDim, fontSize: 10, letterSpacing: 2, marginBottom: 20 },

  wsIndicator: { flexDirection: "row", alignItems: "center", gap: 5 },
  dot:     { width: 8, height: 8, borderRadius: 4 },
  wsText:  { color: THEME.textMuted, fontSize: 10, fontWeight: "700", letterSpacing: 1 },

  errorBox:  { backgroundColor: "#2A0A0F", borderWidth: 1, borderColor: THEME.red, borderRadius: 8, padding: 12, marginBottom: 16 },
  errorText: { color: THEME.red, fontSize: 12 },

  sectionLabel: { color: THEME.textMuted, fontSize: 10, fontWeight: "800", letterSpacing: 2, marginBottom: 8, marginTop: 16 },
  sectionCount: { color: THEME.textDim, fontWeight: "400" },
  statsRow:     { flexDirection: "row", marginBottom: 0 },

  topThreat: { backgroundColor: THEME.bgCard, borderWidth: 1, borderColor: THEME.red, borderRadius: 8, padding: 14, marginBottom: 8 },
  topIoc:    { color: THEME.textPrimary, fontSize: 15, fontWeight: "700", fontFamily: "monospace", marginBottom: 4 },
  topScore:  { fontSize: 32, fontWeight: "900" },
  topMeta:   { color: THEME.textMuted, fontSize: 11, marginTop: 2 },
});
