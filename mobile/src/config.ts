// ─────────────────────────────────────────────
// PHANTØM Mobile — Config
// Replace RENDER_URL with your actual Render URL
// ─────────────────────────────────────────────

export const CONFIG = {
  // PHANTØM backend on Render (no trailing slash)
  API_BASE_URL: "https://your-phantom-app.onrender.com",

  // MOBILE_API_KEY in Render environment variables
  MOBILE_API_KEY: "phantom-mobile-2024",

  // WebSocket (wss for https backends)
  WS_URL: "wss://your-phantom-app.onrender.com/ws",
};

// Severity colors — consistent across all screens
export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#FF2D55",
  HIGH:     "#FF9500",
  MEDIUM:   "#FFD60A",
  LOW:      "#30D158",
  UNKNOWN:  "#636366",
};

// App theme
export const THEME = {
  bg:         "#050A0F",
  bgCard:     "#0A1628",
  bgInput:    "#0D1F3C",
  border:     "#1A3A5C",
  accent:     "#00F5FF",
  accentDim:  "#007A8A",
  red:        "#FF2D55",
  orange:     "#FF9500",
  yellow:     "#FFD60A",
  green:      "#30D158",
  textPrimary:"#E8F4FD",
  textMuted:  "#607B96",
  textDim:    "#3A5070",
};
