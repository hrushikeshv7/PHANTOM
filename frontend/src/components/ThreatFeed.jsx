import { useEffect, useState } from 'react';
import { api } from '../services/api';
export default function ThreatFeed() {
  const [pulses,setPulses]=useState([]);
  const [loading,setLoading]=useState(true);
  const [expanded,setExpanded]=useState(null);
  useEffect(()=>{
    const load=()=>api.feed(20).then(r=>{setPulses(r.data.pulses);setLoading(false);}).catch(()=>setLoading(false));
    load(); const t=setInterval(load,30000); return ()=>clearInterval(t);
  },[]);
  return (
    <div className="panel" style={{display:'flex',flexDirection:'column',height:'100%',overflow:'hidden'}}>
      <div className="panel-header">
        <div style={{width:8,height:8,borderRadius:'50%',background:'#FF1744'}} className="pulse-red"/>
        <span className="red-label" style={{fontSize:11}}>Live Intelligence</span>
        <span className="label" style={{marginLeft:'auto'}}>OTX Global</span>
      </div>
      <div style={{flex:1,overflowY:'auto',minHeight:0}}>
        {loading&&<div style={{color:'var(--gray2)',padding:28,fontSize:13,textAlign:'center'}}>Connecting...</div>}
        {!loading&&pulses.length===0&&<div style={{color:'var(--gray2)',padding:28,fontSize:13,textAlign:'center'}}>No active pulses</div>}
        {pulses.map((p,i)=>(
          <div key={p.id||i} style={{borderBottom:'1px solid var(--border)',padding:'12px 16px',cursor:'pointer',transition:'background .15s'}}
            onMouseEnter={e=>e.currentTarget.style.background='rgba(0,229,255,.03)'}
            onMouseLeave={e=>e.currentTarget.style.background='transparent'}
            onClick={()=>setExpanded(expanded===i?null:i)}>
            <div style={{display:'flex',justifyContent:'space-between',gap:8}}>
              <span style={{fontSize:13,color:'var(--white2)',lineHeight:1.5,flex:1,fontFamily:"'Space Grotesk',sans-serif",fontWeight:500}}>{p.name}</span>
              <span className="mono" style={{fontSize:11,color:'var(--gray2)',whiteSpace:'nowrap',flexShrink:0}}>{p.ioc_count}</span>
            </div>
            {p.tags?.length>0&&<div style={{display:'flex',flexWrap:'wrap',gap:4,marginTop:6}}>{p.tags.slice(0,3).map((t,j)=><span key={j} className="badge-medium" style={{fontSize:9}}>{t}</span>)}</div>}
            <div className="mono" style={{fontSize:10,color:'var(--gray2)',marginTop:5}}>{p.author} · {p.created?.slice(0,10)}</div>
            {expanded===i&&p.description&&(
              <div style={{marginTop:10,paddingTop:10,borderTop:'1px solid var(--border)',fontSize:12,color:'var(--gray)',lineHeight:1.7,fontFamily:"'Space Grotesk',sans-serif"}}>
                {p.description?.slice(0,220)}{p.description?.length>220?'...':''}
                {p.id&&<a href={'https://otx.alienvault.com/pulse/'+p.id} target="_blank" rel="noreferrer" style={{display:'block',marginTop:6,color:'var(--cyan)',fontSize:11,textDecoration:'none',fontFamily:"'Orbitron',sans-serif",fontWeight:600,letterSpacing:'.06em'}}>VIEW SOURCE →</a>}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
