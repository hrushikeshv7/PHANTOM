import React from "react";
import { View, Text, StyleSheet } from "react-native";
import { THEME } from "../config";

interface Props {
  label: string;
  value: string | number;
  color?: string;
  sub?:  string;
}

export const StatCard = ({ label, value, color = THEME.accent, sub }: Props) => (
  <View style={styles.card}>
    <Text style={[styles.value, { color }]}>{value}</Text>
    <Text style={styles.label}>{label}</Text>
    {sub && <Text style={styles.sub}>{sub}</Text>}
  </View>
);

const styles = StyleSheet.create({
  card: {
    flex:            1,
    backgroundColor: THEME.bgCard,
    borderWidth:     1,
    borderColor:     THEME.border,
    borderRadius:    8,
    padding:         14,
    margin:          4,
    alignItems:      "center",
  },
  value: {
    fontSize:   26,
    fontWeight: "900",
    marginBottom: 2,
  },
  label: {
    color:        THEME.textMuted,
    fontSize:     10,
    fontWeight:   "700",
    letterSpacing: 1,
    textTransform: "uppercase",
    textAlign:    "center",
  },
  sub: {
    color:     THEME.textDim,
    fontSize:  10,
    marginTop: 2,
  },
});
