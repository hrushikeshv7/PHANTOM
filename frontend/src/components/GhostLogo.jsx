export default function PhantomMark({ size=32 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none">
      <polygon points="32,4 60,56 4,56" fill="none" stroke="#00E5FF" strokeWidth="1.5" opacity=".9"/>
      <polygon points="32,14 52,50 12,50" fill="none" stroke="#00E5FF" strokeWidth=".6" opacity=".35"/>
      <circle cx="32" cy="38" r="7" fill="#FF1744" opacity=".9"/>
      <circle cx="32" cy="38" r="4" fill="#FF1744"/>
      <circle cx="32" cy="38" r="2" fill="#FFFFFF"/>
      <line x1="32" y1="4" x2="32" y2="18" stroke="#00E5FF" strokeWidth="1.5" opacity=".6"/>
      <circle cx="32" cy="38" r="11" fill="none" stroke="#FF1744" strokeWidth=".6" opacity=".4"/>
    </svg>
  );
}
