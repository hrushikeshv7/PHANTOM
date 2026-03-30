import { useEffect, useState } from 'react';
import { api } from '../services/api';
const SC={CRITICAL:'#FF1744',HIGH:'#FF6D00',MEDIUM:'#FFB300',LOW:'#00E676'};
export default function ScoreBoard() {
  const [data,setData]=useState([]);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{api.leaderboard(10).then(r=>{setData(r.data.leaderboard);setLoading(false);}).catch(()=>setLoading(false));},[]);
  return(
    <div className="panel" style={{display:'flex',flexDirection:'column',height:'100%',overflow:'hidden'}}>
      <div className="panel-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
        <span className="cyan-label" style={{fontSize:11}}>Top Threats</span>
        <span className="label" style={{marginLeft:'auto'}}>Live Ranked</span>
      </div>
      <div style={{flex:1,overflowY:'auto',minHeight:0}}>
        {loading&&<div style={{color:'var(--gray2)',padding:24,fontSize:13,textAlign:'center'}}>Loading...</div>}
        {!loading&&data.length===0&&<div style={{color:'var(--gray2)',padding:24,fontSize:13,textAlign:'center'}}>Run an analysis first</div>}
        {data.map((r,i)=>{
          const color=SC[r.severity]||'#00E676';
          return(
            <div key={i} style={{display:'flex',alignItems:'center',gap:12,padding:'11px 18px',borderBottom:'1px solid var(--border)',transition:'background .15s'}}
              onMouseEnter={e=>e.currentTarget.style.background='rgba(0,229,255,.03)'}
              onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
              <span className="orbitron" style={{fontSize:14,fontWeight:700,color:i<3?color:'var(--gray2)',width:20,flexShrink:0}}>{i+1}</span>
              <div style={{flex:1,minWidth:0}}>
                <div className="mono" style={{fontSize:12,color:'var(--white2)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',fontWeight:500}}>{r.ioc}</div>
                <div style={{fontSize:11,color:'var(--gray2)',marginTop:3,fontFamily:"'Space Grotesk',sans-serif"}}>{r.country||'Unknown'} · {r.ioc_type}</div>
              </div>
              <div style={{textAlign:'right',flexShrink:0}}>
                <div className="orbitron" style={{fontSize:16,fontWeight:700,color}}>{r.threat_score?.toFixed(1)}</div>
                <span className={'badge-'+(r.severity||'low').toLowerCase()} style={{fontSize:9}}>{r.severity}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
