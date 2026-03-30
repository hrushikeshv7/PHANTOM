import { useEffect, useState } from 'react';
import { api } from '../services/api';
const VC={MALICIOUS:'#FF1744',SUSPICIOUS:'#FF6D00','POTENTIALLY UNSAFE':'#FFB300',CLEAN:'#00E676'};
export default function FileHistory(){
  const [files,setFiles]=useState([]);
  const [loading,setLoading]=useState(true);
  const [selected,setSelected]=useState(null);
  const load=()=>api.fileHistory().then(r=>{setFiles(r.data.files||[]);setLoading(false);}).catch(()=>setLoading(false));
  useEffect(()=>{load();const t=setInterval(load,15000);return()=>clearInterval(t);},[]);
  return(
    <div style={{display:'grid',gridTemplateColumns:selected?'1fr 1fr':'1fr',gap:12,height:'100%'}}>
      <div className="panel" style={{display:'flex',flexDirection:'column',height:'100%',overflow:'hidden'}}>
        <div className="panel-header">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FF1744" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span className="red-label" style={{fontSize:11}}>File Analysis History</span>
          <span className="label" style={{marginLeft:'auto'}}>{files.length} SCANNED</span>
        </div>
        {files.length>0&&(
          <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',borderBottom:'1px solid var(--border)'}}>
            {[['Malicious',files.filter(f=>f.verdict==='MALICIOUS').length,'#FF1744'],['Suspicious',files.filter(f=>f.verdict==='SUSPICIOUS').length,'#FF6D00'],['Unsafe',files.filter(f=>f.verdict==='POTENTIALLY UNSAFE').length,'#FFB300'],['Clean',files.filter(f=>f.verdict==='CLEAN').length,'#00E676']].map(([l,v,c],i)=>(
              <div key={i} style={{padding:'10px 14px',borderRight:i<3?'1px solid var(--border)':'none',textAlign:'center'}}>
                <div className="orbitron" style={{fontSize:22,fontWeight:700,color:c}}>{v}</div>
                <div className="label" style={{fontSize:9}}>{l}</div>
              </div>
            ))}
          </div>
        )}
        <div style={{flex:1,overflowY:'auto',minHeight:0}}>
          {loading&&<div style={{color:'var(--gray2)',padding:24,textAlign:'center',fontSize:13}}>Loading history...</div>}
          {!loading&&files.length===0&&<div style={{color:'var(--gray2)',padding:32,textAlign:'center',fontSize:12,lineHeight:2}}>No files analyzed yet<br/><span style={{fontSize:11}}>Upload a file in File Scanner tab</span></div>}
          {files.map((f,i)=>{
            const color=VC[f.verdict]||'#00E676';
            const isOpen=selected?.id===f.id;
            return(
              <div key={f.id||i} style={{borderBottom:'1px solid var(--border)',padding:'12px 16px',cursor:'pointer',transition:'background .15s',background:isOpen?'rgba(0,229,255,.04)':'transparent'}}
                onMouseEnter={e=>{if(!isOpen)e.currentTarget.style.background='rgba(255,255,255,.02)';}}
                onMouseLeave={e=>{if(!isOpen)e.currentTarget.style.background='transparent';}}
                onClick={()=>setSelected(isOpen?null:f)}>
                <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',gap:8}}>
                  <div style={{display:'flex',alignItems:'center',gap:8,minWidth:0}}>
                    <div style={{width:32,height:32,borderRadius:4,background:color+'15',border:'1px solid '+color+'30',display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}>
                      <span className="orbitron" style={{fontSize:8,color,fontWeight:700}}>{f.extension?.replace('.','').toUpperCase().slice(0,4)||'FILE'}</span>
                    </div>
                    <div style={{minWidth:0}}>
                      <div style={{fontSize:12,color:'var(--white2)',fontWeight:500,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{f.filename}</div>
                      <div className="mono" style={{fontSize:10,color:'var(--gray2)',marginTop:2}}>{f.sha256?.slice(0,16)}... · {(f.file_size/1024).toFixed(1)}KB</div>
                    </div>
                  </div>
                  <div style={{textAlign:'right',flexShrink:0}}>
                    <div className="orbitron" style={{fontSize:18,fontWeight:700,color}}>{f.risk_score?.toFixed(0)}</div>
                    <span className={f.verdict==='MALICIOUS'?'badge-critical':f.verdict==='SUSPICIOUS'?'badge-high':f.verdict==='POTENTIALLY UNSAFE'?'badge-medium':'badge-low'} style={{fontSize:9}}>{f.verdict?.slice(0,8)}</span>
                  </div>
                </div>
                {f.findings?.length>0&&(
                  <div style={{display:'flex',flexWrap:'wrap',gap:4,marginTop:8}}>
                    {f.findings.slice(0,3).map((fn,j)=>(
                      <span key={j} style={{fontSize:9,color:'var(--gray)',background:'rgba(255,23,68,.08)',border:'1px solid rgba(255,23,68,.15)',borderRadius:3,padding:'2px 6px'}}>{fn.split(':')[0]||fn.slice(0,30)}</span>
                    ))}
                    {f.findings.length>3&&<span style={{fontSize:9,color:'var(--gray2)'}}>+{f.findings.length-3} more</span>}
                  </div>
                )}
                <div className="mono" style={{fontSize:9,color:'var(--gray2)',marginTop:6}}>{f.created_at?.slice(0,19).replace('T',' ')} UTC · Click for details</div>
              </div>
            );
          })}
        </div>
      </div>
      {selected&&(
        <div className="panel fade-up" style={{display:'flex',flexDirection:'column',overflow:'hidden'}}>
          <div className="panel-header">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            <span className="cyan-label" style={{fontSize:11}}>Analysis Detail</span>
            <button onClick={()=>setSelected(null)} style={{marginLeft:'auto',background:'none',border:'none',color:'var(--gray2)',cursor:'pointer',fontSize:18,lineHeight:1}}>x</button>
          </div>
          <div style={{flex:1,overflowY:'auto',padding:'16px 18px',display:'flex',flexDirection:'column',gap:14}}>
            <div style={{display:'flex',alignItems:'flex-end',justifyContent:'space-between',padding:'14px 16px',background:(VC[selected.verdict]||'#00E676')+'0d',borderLeft:'3px solid '+(VC[selected.verdict]||'#00E676'),borderRadius:'0 8px 8px 0'}}>
              <div>
                <div className="orbitron" style={{fontSize:20,fontWeight:700,color:VC[selected.verdict]||'#00E676',letterSpacing:2}}>{selected.verdict}</div>
                <div style={{fontSize:12,color:'var(--gray2)',marginTop:3}}>{selected.filename}</div>
              </div>
              <div style={{textAlign:'right'}}>
                <div className="orbitron" style={{fontSize:44,color:VC[selected.verdict]||'#00E676',lineHeight:1,fontWeight:900}}>{selected.risk_score?.toFixed(0)}</div>
                <div className="label" style={{marginTop:2}}>Risk Score</div>
              </div>
            </div>
            <div className="score-bar"><div className="score-fill" style={{width:selected.risk_score+'%',background:VC[selected.verdict]||'#00E676'}}/></div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
              {[['Extension',selected.extension||'—'],['Size',(selected.file_size/1024).toFixed(1)+' KB'],['SHA256',selected.sha256?.slice(0,16)+'...'],['Date',selected.created_at?.slice(0,10)]].map(([l,v])=>(
                <div key={l} style={{background:'var(--surface)',border:'1px solid var(--border)',borderRadius:6,padding:'8px 12px'}}>
                  <div className="label" style={{marginBottom:4}}>{l}</div>
                  <div className="mono" style={{fontSize:11,color:'var(--white)'}}>{v}</div>
                </div>
              ))}
            </div>
            {selected.findings?.length>0&&(
              <div style={{background:'rgba(255,23,68,.05)',border:'1px solid rgba(255,23,68,.15)',borderRadius:6,padding:'12px 14px'}}>
                <div className="label" style={{color:'var(--red)',marginBottom:10}}>All Detections ({selected.findings.length})</div>
                {selected.findings.map((f,i)=><div key={i} style={{fontSize:11,color:'var(--white2)',marginBottom:6,paddingLeft:12,borderLeft:'2px solid rgba(255,23,68,.3)',lineHeight:1.6}}>{f}</div>)}
              </div>
            )}
            {selected.ai_analysis&&(
              <div style={{background:'rgba(255,23,68,.04)',borderLeft:'3px solid var(--red)',padding:'14px 16px',borderRadius:'0 8px 8px 0'}}>
                <div className="red-label" style={{marginBottom:10,fontSize:11}}>AI Deep Analysis</div>
                <pre style={{fontSize:11,color:'var(--white2)',fontFamily:"'JetBrains Mono',monospace",whiteSpace:'pre-wrap',lineHeight:1.8}}>{selected.ai_analysis}</pre>
              </div>
            )}
            {!selected.ai_analysis&&<div style={{color:'var(--gray2)',fontSize:12}}>No AI analysis for this file.</div>}
          </div>
        </div>
      )}
    </div>
  );
}
