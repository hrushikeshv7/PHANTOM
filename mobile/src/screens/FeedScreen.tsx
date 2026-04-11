import React, { useEffect, useState, useCallback } from "react";
import {
  View, Text, FlatList, StyleSheet,
  RefreshControl, ActivityIndicator, TouchableOpacity,
} from "react-native";
import { getLiveFeed, Pulse } from "../api/client";
import { THEME } from "../config";

export const FeedScreen = () => {
  const [pulses,     setPulses]     = useState<Pulse[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expanded,   setExpanded]   = useState<string | null>(null);

  const fetch = useCallback(async () => {
    try {
      const data = await getLiveFeed();
      setPulses(data.pulses);
    } catch (_) {}
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { fetch(); }, []);

  if (loading) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator size="large" color={THEME.accent} />
      </View>
    );
  }

  const renderPulse = ({ item }: { item: Pulse }) => {
    const isOpen = expanded === item.id;
    return (
      <TouchableOpacity
        style={styles.card}
        onPress={() => setExpanded(isOpen ? null : item.id)}
        activeOpacity={0.8}
      >
        <View style={styles.cardHeader}>
          <View style={styles.pulseDot} />
          <Text style={styles.pulseName} numberOfLines={isOpen ? 10 : 2}>{item.name}</Text>
        </View>

        {item.tags?.length > 0 && (
          <View style={styles.tagRow}>
            {item.tags.slice(0, 4).map((tag, i) => (
              <View key={i} style={styles.tag}>
                <Text style={styles.tagText}>{tag}</Text>
              </View>
            ))}
          </View>
        )}

        {isOpen && item.description ? (
          <Text style={styles.desc}>{item.description}</Text>
        ) : null}

        <Text style={styles.time}>{new Date(item.created).toLocaleString()}</Text>
      </TouchableOpacity>
    );
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>LIVE FEED</Text>
        <View style={styles.liveIndicator}>
          <View style={styles.liveDot} />
          <Text style={styles.liveText}>OTX</Text>
        </View>
      </View>
      <Text style={styles.subtitle}>{pulses.length} global threat pulses</Text>

      <FlatList
        data={pulses}
        keyExtractor={(p) => p.id}
        renderItem={renderPulse}
        contentContainerStyle={styles.list}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={() => { setRefreshing(true); fetch(); }}
            tintColor={THEME.accent}
          />
        }
        ListEmptyComponent={
          <Text style={styles.empty}>No pulses available.</Text>
        }
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: THEME.bg },
  centered:  { flex: 1, backgroundColor: THEME.bg, justifyContent: "center", alignItems: "center" },
  header:    { flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16, paddingBottom: 4 },
  title:     { color: THEME.accent, fontSize: 22, fontWeight: "900", letterSpacing: 3 },
  subtitle:  { color: THEME.textMuted, fontSize: 11, paddingHorizontal: 16, marginBottom: 12 },

  liveIndicator: { flexDirection: "row", alignItems: "center", gap: 5 },
  liveDot:       { width: 8, height: 8, borderRadius: 4, backgroundColor: THEME.green },
  liveText:      { color: THEME.green, fontSize: 10, fontWeight: "800", letterSpacing: 1 },

  list: { paddingHorizontal: 16, paddingBottom: 32 },
  card: {
    backgroundColor: THEME.bgCard,
    borderWidth:     1,
    borderColor:     THEME.border,
    borderRadius:    8,
    padding:         12,
    marginBottom:    8,
  },
  cardHeader: { flexDirection: "row", alignItems: "flex-start", gap: 8, marginBottom: 8 },
  pulseDot:   { width: 6, height: 6, borderRadius: 3, backgroundColor: THEME.accent, marginTop: 5 },
  pulseName:  { color: THEME.textPrimary, fontSize: 13, fontWeight: "600", flex: 1, lineHeight: 18 },
  tagRow:     { flexDirection: "row", flexWrap: "wrap", gap: 4, marginBottom: 6 },
  tag:        { backgroundColor: THEME.accentDim + "30", borderWidth: 1, borderColor: THEME.accentDim, borderRadius: 4, paddingHorizontal: 6, paddingVertical: 2 },
  tagText:    { color: THEME.accent, fontSize: 9, fontWeight: "700" },
  desc:       { color: THEME.textMuted, fontSize: 12, lineHeight: 18, marginBottom: 6 },
  time:       { color: THEME.textDim, fontSize: 10 },
  empty:      { color: THEME.textMuted, textAlign: "center", marginTop: 40 },
});
