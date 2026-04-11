import React, { useState } from "react";
import {
  View, Text, TextInput, StyleSheet, TouchableOpacity,
  ScrollView, ActivityIndicator, Keyboard,
} from "react-native";
import { analyzeIOC, IOCResult } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { THEME, SEVERITY_COLORS } from "../config";

const IOC_TYPES = ["ip", "domain", "hash"];

export const IOCLookupScreen = () => {
  const [ioc,     setIoc]     = useState("");
  const [type,    setType]    = useState("ip");
  const [result,  setResult]  = useState<IOCResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  const analyze = async () => {
    if (!ioc.trim()) return;
    Keyboard.dismiss();
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyzeIOC(ioc.trim(), type);
      setResult(data);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? "Analysis failed. Check your IOC.");
    } finally {
      setLoading(false);
    }
  };

  const scoreColor = result
    ? result.threat_score >= 70
      ? THEME.red
      : result.threat_score >= 40
      ? THEME.orange
      : THEME.green
    : THEME.accent;

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
      <Text style={styles.title}>IOC LOOKUP</Text>
      <Text style={styles.subtitle}>Analyze any IP · Domain · Hash</Text>

      {/* IOC Type selector */}
      <View style={styles.typeRow}>
        {IOC_TYPES.map((t) => (
          <TouchableOpacity
            key={t}
            style={[styles.typePill, type === t && styles.typePillActive]}
            onPress={() => setType(t)}
          >
            <Text style={[styles.typeText, type === t && styles.typeTextActive]}>
              {t.toUpperCase()}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      {/* Input */}
      <View style={styles.inputWrapper}>
        <TextInput
          style={styles.input}
          placeholder={
            type === "ip"     ? "e.g. 192.168.1.1" :
            type === "domain" ? "e.g. malware.io"   :
                                "e.g. d41d8cd98f00b204..."
          }
          placeholderTextColor={THEME.textDim}
          value={ioc}
          onChangeText={setIoc}
          autoCapitalize="none"
          autoCorrect={false}
          onSubmitEditing={analyze}
        />
        <TouchableOpacity
          style={[styles.analyzeBtn, loading && styles.analyzeBtnDisabled]}
          onPress={analyze}
          disabled={loading}
        >
          {loading
            ? <ActivityIndicator size="small" color={THEME.bg} />
            : <Text style={styles.analyzeBtnText}>SCAN</Text>
          }
        </TouchableOpacity>
      </View>

      {error && (
        <View style={styles.errorBox}>
          <Text style={styles.errorText}>{error}</Text>
        </View>
      )}

      {/* Result */}
      {result && (
        <View style={styles.resultCard}>
          {/* Score circle */}
          <View style={styles.scoreBlock}>
            <Text style={[styles.scoreNum, { color: scoreColor }]}>
              {result.threat_score.toFixed(1)}
            </Text>
            <Text style={styles.scoreLabel}>/ 100</Text>
          </View>

          <View style={styles.resultMeta}>
            <SeverityBadge severity={result.severity} />
            {result.country && (
              <Text style={styles.metaItem}>🌍 {result.country}</Text>
            )}
            {result.ioc_type && (
              <Text style={styles.metaItem}>TYPE: {result.ioc_type.toUpperCase()}</Text>
            )}
          </View>

          {result.ai_summary && (
            <View style={styles.summaryBox}>
              <Text style={styles.summaryLabel}>◈ AI ANALYST BRIEFING</Text>
              <Text style={styles.summaryText}>{result.ai_summary}</Text>
            </View>
          )}

          {result.record_id && (
            <Text style={styles.recordId}>Record #{result.record_id}</Text>
          )}
        </View>
      )}

      {/* Quick examples */}
      {!result && !loading && (
        <View style={styles.examples}>
          <Text style={styles.exampleLabel}>QUICK TEST</Text>
          {["1.1.1.1", "google.com", "44d88612fea8a8f36de82e1278abb02f"].map((ex) => (
            <TouchableOpacity
              key={ex}
              style={styles.examplePill}
              onPress={() => { setIoc(ex); setType(ex.includes(".") && !ex.includes(" ") && ex.split(".").length === 4 ? "ip" : ex.length > 20 ? "hash" : "domain"); }}
            >
              <Text style={styles.exampleText}>{ex}</Text>
            </TouchableOpacity>
          ))}
        </View>
      )}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: THEME.bg },
  content:   { padding: 16, paddingBottom: 40 },
  title:     { color: THEME.accent, fontSize: 22, fontWeight: "900", letterSpacing: 3, marginBottom: 4 },
  subtitle:  { color: THEME.textMuted, fontSize: 11, letterSpacing: 1, marginBottom: 20 },

  typeRow:        { flexDirection: "row", gap: 8, marginBottom: 12 },
  typePill:       { borderWidth: 1, borderColor: THEME.border, borderRadius: 6, paddingHorizontal: 14, paddingVertical: 7 },
  typePillActive: { borderColor: THEME.accent, backgroundColor: THEME.accent + "15" },
  typeText:       { color: THEME.textMuted, fontSize: 11, fontWeight: "700" },
  typeTextActive: { color: THEME.accent },

  inputWrapper: { flexDirection: "row", gap: 8, marginBottom: 12 },
  input:        { flex: 1, backgroundColor: THEME.bgInput, borderWidth: 1, borderColor: THEME.border, borderRadius: 8, padding: 12, color: THEME.textPrimary, fontSize: 13, fontFamily: "monospace" },
  analyzeBtn:         { backgroundColor: THEME.accent, borderRadius: 8, paddingHorizontal: 18, justifyContent: "center", alignItems: "center" },
  analyzeBtnDisabled: { backgroundColor: THEME.accentDim },
  analyzeBtnText:     { color: THEME.bg, fontWeight: "900", fontSize: 12, letterSpacing: 1 },

  errorBox:  { backgroundColor: "#2A0A0F", borderWidth: 1, borderColor: THEME.red, borderRadius: 8, padding: 12, marginBottom: 12 },
  errorText: { color: THEME.red, fontSize: 12 },

  resultCard:  { backgroundColor: THEME.bgCard, borderWidth: 1, borderColor: THEME.border, borderRadius: 12, padding: 16, marginBottom: 16 },
  scoreBlock:  { flexDirection: "row", alignItems: "flex-end", marginBottom: 12 },
  scoreNum:    { fontSize: 52, fontWeight: "900", lineHeight: 56 },
  scoreLabel:  { color: THEME.textMuted, fontSize: 18, marginBottom: 6, marginLeft: 4 },
  resultMeta:  { flexDirection: "row", flexWrap: "wrap", gap: 8, marginBottom: 14 },
  metaItem:    { color: THEME.textMuted, fontSize: 12 },
  summaryBox:  { backgroundColor: "#081830", borderWidth: 1, borderColor: THEME.accentDim, borderRadius: 8, padding: 12, marginBottom: 10 },
  summaryLabel:{ color: THEME.accent, fontSize: 10, fontWeight: "800", letterSpacing: 1.5, marginBottom: 6 },
  summaryText: { color: THEME.textPrimary, fontSize: 13, lineHeight: 20 },
  recordId:    { color: THEME.textDim, fontSize: 10, textAlign: "right" },

  examples:     { marginTop: 20 },
  exampleLabel: { color: THEME.textDim, fontSize: 10, letterSpacing: 2, marginBottom: 10 },
  examplePill:  { backgroundColor: THEME.bgCard, borderWidth: 1, borderColor: THEME.border, borderRadius: 6, padding: 10, marginBottom: 6 },
  exampleText:  { color: THEME.textMuted, fontSize: 12, fontFamily: "monospace" },
});
