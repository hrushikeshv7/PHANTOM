import React, { useState } from "react";
import {
  View, Text, TextInput, StyleSheet,
  TouchableOpacity, ScrollView, Clipboard,
} from "react-native";
import { THEME } from "../config";

// ── Utility functions (fully offline) ─────────────────────────
const tools = {
  "Base64 Encode":  (s: string) => btoa(unescape(encodeURIComponent(s))),
  "Base64 Decode":  (s: string) => { try { return decodeURIComponent(escape(atob(s))); } catch { return "Invalid Base64"; } },
  "URL Encode":     (s: string) => encodeURIComponent(s),
  "URL Decode":     (s: string) => { try { return decodeURIComponent(s); } catch { return "Invalid URL encoding"; } },
  "Hex → ASCII":    (s: string) => { try { return s.replace(/\s/g,"").match(/.{2}/g)?.map(b=>String.fromCharCode(parseInt(b,16))).join("")??""; } catch { return "Invalid hex"; } },
  "ASCII → Hex":    (s: string) => Array.from(s).map(c=>c.charCodeAt(0).toString(16).padStart(2,"0")).join(" "),
  "ROT13":          (s: string) => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13))),
  "Reverse String": (s: string) => s.split("").reverse().join(""),
  "Count Chars":    (s: string) => `Length: ${s.length} | Words: ${s.trim().split(/\s+/).filter(Boolean).length}`,
  "Hash Identify":  (s: string) => {
    const len = s.replace(/\s/g,"").length;
    if (/^[a-fA-F0-9]+$/.test(s.trim())) {
      if (len === 32)  return "MD5 (128-bit)";
      if (len === 40)  return "SHA1 (160-bit)";
      if (len === 56)  return "SHA224";
      if (len === 64)  return "SHA256 (256-bit)";
      if (len === 96)  return "SHA384";
      if (len === 128) return "SHA512 (512-bit)";
      return `Unknown hex hash (${len} chars)`;
    }
    if (s.startsWith("$2"))  return "bcrypt";
    if (s.startsWith("$1$")) return "MD5-crypt";
    if (s.startsWith("$5$")) return "SHA256-crypt";
    if (s.startsWith("$6$")) return "SHA512-crypt";
    return "Unknown / not a hash";
  },
};

const CATEGORIES: Record<string, string[]> = {
  "ENCODING": ["Base64 Encode", "Base64 Decode", "URL Encode", "URL Decode"],
  "CONVERSION": ["Hex → ASCII", "ASCII → Hex"],
  "CIPHER":   ["ROT13", "Reverse String"],
  "ANALYSIS": ["Hash Identify", "Count Chars"],
};

export const ToolkitScreen = () => {
  const [input,       setInput]       = useState("");
  const [activeTool,  setActiveTool]  = useState<string | null>(null);
  const [output,      setOutput]      = useState<string | null>(null);
  const [copied,      setCopied]      = useState(false);

  const run = (tool: string) => {
    setActiveTool(tool);
    const fn = (tools as any)[tool];
    if (fn && input.trim()) {
      setOutput(fn(input));
    } else if (!input.trim()) {
      setOutput("⚠ Enter input first.");
    }
  };

  const copy = () => {
    if (output) {
      Clipboard.setString(output);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.title}>CTF TOOLKIT</Text>
      <Text style={styles.subtitle}>100% OFFLINE · NO NETWORK NEEDED</Text>

      {/* Input */}
      <View style={styles.inputSection}>
        <Text style={styles.sectionLabel}>INPUT</Text>
        <TextInput
          style={styles.input}
          placeholder="Paste text, hash, hex, or encoded string..."
          placeholderTextColor={THEME.textDim}
          value={input}
          onChangeText={(t) => { setInput(t); setOutput(null); setActiveTool(null); }}
          multiline
          autoCapitalize="none"
          autoCorrect={false}
        />
      </View>

      {/* Tool categories */}
      {Object.entries(CATEGORIES).map(([cat, toolList]) => (
        <View key={cat} style={styles.category}>
          <Text style={styles.catLabel}>{cat}</Text>
          <View style={styles.toolGrid}>
            {toolList.map((tool) => (
              <TouchableOpacity
                key={tool}
                style={[styles.toolBtn, activeTool === tool && styles.toolBtnActive]}
                onPress={() => run(tool)}
              >
                <Text style={[styles.toolText, activeTool === tool && styles.toolTextActive]}>
                  {tool}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>
      ))}

      {/* Output */}
      {output && (
        <View style={styles.outputSection}>
          <View style={styles.outputHeader}>
            <Text style={styles.sectionLabel}>OUTPUT — {activeTool}</Text>
            <TouchableOpacity onPress={copy} style={styles.copyBtn}>
              <Text style={styles.copyText}>{copied ? "COPIED ✓" : "COPY"}</Text>
            </TouchableOpacity>
          </View>
          <View style={styles.outputBox}>
            <Text style={styles.outputText} selectable>{output}</Text>
          </View>
        </View>
      )}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: THEME.bg },
  content:   { padding: 16, paddingBottom: 40 },
  title:     { color: THEME.accent, fontSize: 22, fontWeight: "900", letterSpacing: 3, marginBottom: 2 },
  subtitle:  { color: THEME.textMuted, fontSize: 10, letterSpacing: 2, marginBottom: 20 },
  sectionLabel: { color: THEME.textMuted, fontSize: 9, fontWeight: "800", letterSpacing: 2, marginBottom: 8 },

  inputSection: { marginBottom: 16 },
  input: {
    backgroundColor: THEME.bgInput,
    borderWidth:     1,
    borderColor:     THEME.border,
    borderRadius:    8,
    padding:         12,
    color:           THEME.textPrimary,
    fontSize:        13,
    fontFamily:      "monospace",
    minHeight:       80,
    textAlignVertical: "top",
  },

  category:  { marginBottom: 16 },
  catLabel:  { color: THEME.textDim, fontSize: 9, fontWeight: "800", letterSpacing: 2, marginBottom: 8, borderLeftWidth: 2, borderLeftColor: THEME.accent, paddingLeft: 8 },
  toolGrid:  { flexDirection: "row", flexWrap: "wrap", gap: 6 },
  toolBtn:      { borderWidth: 1, borderColor: THEME.border, borderRadius: 6, paddingHorizontal: 12, paddingVertical: 8, backgroundColor: THEME.bgCard },
  toolBtnActive:{ borderColor: THEME.accent, backgroundColor: THEME.accent + "15" },
  toolText:      { color: THEME.textMuted, fontSize: 11, fontWeight: "600" },
  toolTextActive:{ color: THEME.accent },

  outputSection: { marginTop: 8 },
  outputHeader:  { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 8 },
  copyBtn:       { backgroundColor: THEME.accentDim + "40", borderWidth: 1, borderColor: THEME.accentDim, borderRadius: 5, paddingHorizontal: 10, paddingVertical: 4 },
  copyText:      { color: THEME.accent, fontSize: 10, fontWeight: "800", letterSpacing: 1 },
  outputBox:     { backgroundColor: THEME.bgCard, borderWidth: 1, borderColor: THEME.accent + "40", borderRadius: 8, padding: 14 },
  outputText:    { color: THEME.textPrimary, fontSize: 13, fontFamily: "monospace", lineHeight: 20 },
});
