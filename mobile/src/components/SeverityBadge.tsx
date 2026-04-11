import React, { useState } from "react";
import { View, Text, StyleSheet, TouchableOpacity, Animated } from "react-native";
import { Threat } from "../api/client";
import { SeverityBadge } from "./SeverityBadge";
import { THEME, SEVERITY_COLORS } from "../config";

interface Props {
  threat: Threat;
}

export const ThreatCard = ({ threat }: Props) => {
  const [expanded, setExpanded] = useState(false);
  const color = SEVERITY_COLORS[threat.severity] ?? THEME.textMuted;

  return (
    <TouchableOpacity
      style={[styles.card, { borderLeftColor: color }]}
      onPress={() => setExpanded(!expanded)}
      activeOpacity={0.8}
    >
      {/* Top row */}
      <View style={styles.row}>
        <Text style={styles.ioc} numberOfLines={1}>{threat.ioc}</Text>
        <SeverityBadge severity={threat.severity} size="sm" />
      </View>

      {/* Score + meta */}
      <View style={styles.meta}>
        <Text style={[styles.score, { color }]}>{threat.threat_score.toFixed(1)}</Text>
        <Text style={styles.metaText}>/ 100</Text>
        <Text style={styles.dot}>·</Text>
        <Text style={styles.metaText}>{threat.ioc_type?.toUpperCase()}</Text>
        {threat.country && (
          <>
            <Text style={styles.dot}>·</Text>
            <Text style={styles.metaText}>{threat.country}</Text>
          </>
        )}
      </View>

      {/* Expanded AI summary */}
      {expanded && threat.ai_summary && (
        <View style={styles.summary}>
          <Text style={styles.summaryLabel}>AI BRIEFING</Text>
          <Text style={styles.summaryText}>{threat.ai_summary}</Text>
        </View>
      )}

      {/* Timestamp */}
      <Text style={styles.time}>
        {new Date(threat.created_at).toLocaleString()}
      </Text>
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: THEME.bgCard,
    borderWidth:     1,
    borderColor:     THEME.border,
    borderLeftWidth: 3,
    borderRadius:    8,
    padding:         12,
    marginBottom:    8,
  },
  row: {
    flexDirection:  "row",
    justifyContent: "space-between",
    alignItems:     "center",
    marginBottom:   6,
  },
  ioc: {
    color:      THEME.textPrimary,
    fontSize:   14,
    fontWeight: "700",
    flex:       1,
    marginRight: 8,
    fontFamily: "monospace",
  },
  meta: {
    flexDirection: "row",
    alignItems:    "center",
    marginBottom:  4,
  },
  score: {
    fontSize:   18,
    fontWeight: "900",
  },
  metaText: {
    color:    THEME.textMuted,
    fontSize: 11,
    marginLeft: 3,
  },
  dot: {
    color:    THEME.textDim,
    fontSize: 11,
    marginLeft: 3,
  },
  summary: {
    marginTop:       8,
    padding:         10,
    backgroundColor: "#0A1F35",
    borderRadius:    6,
    borderWidth:     1,
    borderColor:     THEME.accentDim,
  },
  summaryLabel: {
    color:         THEME.accent,
    fontSize:      9,
    fontWeight:    "800",
    letterSpacing: 1.5,
    marginBottom:  4,
  },
  summaryText: {
    color:      THEME.textPrimary,
    fontSize:   12,
    lineHeight: 18,
  },
  time: {
    color:    THEME.textDim,
    fontSize: 10,
    marginTop: 6,
  },
});
