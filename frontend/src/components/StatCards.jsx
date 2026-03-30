import { useEffect, useState } from 'react';
import { api } from '../services/api';
const CARDS = [
  { key:'total_analyzed', label:'Total Analyzed', color:'#00E5FF', glow:'glow-cyan',   acc:'rgba(0,229,255,.12)', brd:'rgba(0,229,255,.25)', sub:'all time' },
  { key:'critical_count', label:'Critical',       color:'#FF1744', glow:'glow-red',    acc:'rgba(255,23,68,.12)', brd:'rgba(255,23,68,.3)',  sub:'score 80+' },
  { key:'high_count',     label:'High Severity',  color:'#FF6D00', glow:'glow-orange', acc:'rgba(255,109,0,.1)', brd:'rgba(255,109,0,.25)', sub:'score 60+' },
  { key:'avg_score',      label:'Avg Score',      color:'#FFB300', glow:'glow-amber',  acc:'rgba(255,179,0,.1)', brd:'rgba(255,179,0,.25)', sub:'composite' },
  { key:'_alert',         label:'Alert Threshold',color:'#00E676', glow:'glow-green',  acc:'rgba(0,230,118,.08)',brd:'rgba(0,230,118,.2)', sub:'auto-fire', fixed:'60' },
];
export default function StatCards() {
  const [stats, setStats] = useState(null);
  useEffect(() => {
    const load = () => api.stats().then(r=>setStats(r.data)).catch(()=>{});
    load(); const t=setInterval(load,15000); return ()=>clearInterval(t);
  },[]);
  return (
    <div style={{display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:10,marginBottom:12}}>
      {CARDS.map((c,i)=>{
        const val = c.fixed ?? (stats?stats[c.key]:'—') ?? '—';
        return (
          <div key={i} className="panel fade-up"
            style={{padding:'18px 20px',animationDelay:i*60+'ms',borderColor:c.brd,background:`linear-gradient(135deg,${c.acc},var(--panel))`,cursor:'default',transition:'transform .2s,box-shadow .2s'}}
            onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow=`0 8px 32px ${c.acc}`;}}
            onMouseLeave={e=>{e.currentTarget.style.transform='translateY(0)';e.currentTarget.style.boxShadow='none';}}>
            <div className="label" style={{marginBottom:12}}>{c.label}</div>
            <div className={`orbitron ${c.glow}`} style={{fontSize:40,fontWeight:900,color:c.color,lineHeight:1,marginBottom:6}}>{val}</div>
            <div style={{fontSize:11,color:'var(--gray2)',fontFamily:"'Space Grotesk',sans-serif",fontWeight:500}}>{c.sub}</div>
          </div>
        );
      })}
    </div>
  );
}
