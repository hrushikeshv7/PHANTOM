import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import { api } from '../services/api';
const SC={CRITICAL:'#FF1744',HIGH:'#FF6D00',MEDIUM:'#FFB300',LOW:'#00E676'};
const Tip=({active,payload})=>{
  if(!active||!payload?.length)return null;
  const d=payload[0].payload,c=SC[d.severity]||'#00E676';
  return(<div style={{background:'var(--panel2)',border:'1px solid var(--border2)',borderRadius:6,padding:'10px 14px',fontFamily:"'Space Grotesk',sans-serif"}}>
    <div className="mono" style={{fontSize:11,color:'var(--gray)',marginBottom:4}}>{d.ioc}</div>
    <div className="orbitron" style={{fontSize:22,color:c,fontWeight:700}}>{d.threat_score?.toFixed(1)}</div>
    <span className={'badge-'+(d.severity||'low').toLowerCase()} style={{fontSize:9}}>{d.severity}</span>
  </div>);
};
export default function ThreatChart(){
  const [data,setData]=useState([]);
  useEffect(()=>{api.threats().then(r=>setData(r.data.threats.slice(0,20).reverse())).catch(()=>{});},[]);
  return(
    <div className="panel" style={{padding:'16px 20px'}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:18}}>
        <span className="cyan-label" style={{fontSize:12}}>Score History</span>
        <span className="label">Last 20 Analyses</span>
      </div>
      {data.length===0
        ?<div style={{textAlign:'center',color:'var(--gray2)',padding:'32px 0',fontSize:13}}>No data yet</div>
        :<ResponsiveContainer width="100%" height={175}>
          <BarChart data={data} margin={{top:4,right:4,bottom:4,left:-20}}>
            <CartesianGrid strokeDasharray="2 6" stroke="rgba(255,255,255,.04)" vertical={false}/>
            <XAxis dataKey="ioc" tick={false} axisLine={false} tickLine={false}/>
            <YAxis domain={[0,100]} tick={{fill:'var(--gray2)',fontSize:10,fontFamily:"'JetBrains Mono',monospace"}} axisLine={false} tickLine={false}/>
            <Tooltip content={<Tip/>} cursor={{fill:'rgba(255,255,255,.03)'}}/>
            <Bar dataKey="threat_score" radius={[2,2,0,0]}>
              {data.map((d,i)=><Cell key={i} fill={SC[d.severity]||'#00E676'} fillOpacity={.85}/>)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      }
    </div>
  );
}
