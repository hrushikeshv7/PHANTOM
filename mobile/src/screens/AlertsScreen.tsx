import React, { useEffect, useState, useCallback } from "react";
import {
  View, Text, StyleSheet, FlatList,
  TouchableOpacity, RefreshControl, ActivityIndicator,
} from "react-native";
import { getThreats, Threat } from "../api/client";
import { ThreatCard } from "../components/ThreatCard";
import { THEME, SEVERITY_COLORS } from "../config";

const FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export const AlertsScreen = () => {
  const [threats,    setThreats]    = useState<Threat[]>([]);
  const [filter,     setFilter]     = useState("ALL");
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetch = useCallback(async (sev?: string) => {
    try {
      const data = await getThreats(sev === "ALL" ? undefined : sev);
      setThreats(data.threats);
    } catch (_) {}
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { fetch(filter); }, [filter]);

  if (loading) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator size="large" color={THEME.accent} />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>ALERTS</Text>
        <Text style={styles.count}>{threats.length} records</Text>
      </View>

      {/* Severity filter pills */}
      <View style={styles.filters}>
        {FILTERS.map((f) => {
          const active = filter === f;
          const color  = SEVERITY_COLORS[f] ?? THEME.accent;
          return (
            <TouchableOpacity
              key={f}
              style={[styles.pill, active && { backgroundColor: color + "25", borderColor: color }]}
              onPress={() => setFilter(f)}
            >
              <Text style={[styles.pillText, active && { color }]}>{f}</Text>
            </TouchableOpacity>
          );
        })}
      </View>

      {/* List */}
      <FlatList
        data={threats}
        keyExtractor={(t) => String(t.id)}
        renderItem={({ item }) => <ThreatCard threat={item} />}
        contentContainerStyle={styles.list}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={() => { setRefreshing(true); fetch(filter); }}
            tintColor={THEME.accent}
          />
        }
        ListEmptyComponent={
          <Text style={styles.empty}>No threats found for this filter.</Text>
        }
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: THEME.bg },
  centered:  { flex: 1, backgroundColor: THEME.bg, justifyContent: "center", alignItems: "center" },
  header:    { flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16, paddingBottom: 8 },
  title:     { color: THEME.accent, fontSize: 22, fontWeight: "900", letterSpacing: 3 },
  count:     { color: THEME.textMuted, fontSize: 11 },
  filters:   { flexDirection: "row", paddingHorizontal: 12, paddingBottom: 8, gap: 6 },
  pill:      { borderWidth: 1, borderColor: THEME.border, borderRadius: 20, paddingHorizontal: 10, paddingVertical: 5 },
  pillText:  { color: THEME.textMuted, fontSize: 10, fontWeight: "700", letterSpacing: 1 },
  list:      { padding: 16, paddingTop: 4 },
  empty:     { color: THEME.textMuted, textAlign: "center", marginTop: 40, fontSize: 13 },
});
