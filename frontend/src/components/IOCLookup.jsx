import { useState } from 'react';
import { api, getSeverityColor, getSeverityClass } from '../services/api';
const SC={CRITICAL:'#FF1744',HIGH:'#FF6D00',MEDIUM:'#FFB300',LOW:'#00E676'};
const GC={CRITICAL:'glow-red',HIGH:'glow-orange',MEDIUM:'glow-amber',LOW:'glow-green'};
export default function IOCLookup({onScanComplete}){
  const [ioc,setIoc]=useState('');
  const [type,setType]=useState('ip');
  const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false);
  const [error,setError]=useState(null);
  const analyze=async()=>{
    if(!ioc.trim())return;
    setLoading(true);setError(null);setResult(null);
    try{const r=await api.analyze(ioc.trim(),type,true);setResult(r.data);if(onScanComplete)onScanComplete();}
    catch(e){setError(e.response?.data?.detail||'Analysis failed.');}
    finally{setLoading(false);}
  };
  const color=SC[result?.severity]||'var(--cyan)';
  const glow=GC[result?.severity]||'glow-cyan';
  return(
    <div className="panel" style={{display:'flex',flexDirection:'column',height:'100%',overflow:'hidden'}}>
      <div className="panel-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        <span className="cyan-label" style={{fontSize:12}}>IOC Analyzer</span>
      </div>
      <div style={{padding:'14px 18px',borderBottom:'1px solid var(--border)',flexShrink:0}}>
        <div style={{display:'flex',gap:6,marginBottom:10}}>
          {['ip','domain','hash'].map(t=>(
            <button key={t} className="ph-btn" onClick={()=>setType(t)}
              style={{fontSize:10,padding:'6px 14px',borderColor:type===t?'var(--cyan)':'var(--border2)',color:type===t?'var(--cyan)':'var(--gray2)',boxShadow:type===t?'0 0 10px rgba(0,229,255,.2)':'none'}}>
              {t.toUpperCase()}
            </button>
          ))}
        </div>
        <div style={{display:'flex',gap:8}}>
          <input className="ph-input" value={ioc} onChange={e=>setIoc(e.target.value)}
            onKeyDown={e=>e.key==='Enter'&&analyze()}
            placeholder={'Enter '+type+' to analyze...'} style={{flex:1,fontSize:14}}/>
          <button className="ph-btn-primary" onClick={analyze} disabled={loading} style={{fontSize:12}}>
            {loading?'...':'SCAN'}
          </button>
        </div>
        {error&&<div style={{marginTop:8,fontSize:12,color:'var(--red)'}}>{error}</div>}
      </div>
      <div style={{flex:1,overflowY:'auto',minHeight:0,padding:'16px 18px'}}>
        {!result&&!loading&&(
          <div style={{color:'var(--gray2)',fontSize:13,textAlign:'center',paddingTop:40,lineHeight:2}}>
            Enter an IP address, domain,<br/>or file hash to begin analysis
          </div>
        )}
        {result&&(
          <div className="fade-up" style={{display:'flex',flexDirection:'column',gap:14}}>
            <div style={{display:'flex',alignItems:'flex-end',justifyContent:'space-between'}}>
              <div>
                <div className="label" style={{marginBottom:8}}>Threat Score</div>
                <div className={`orbitron ${glow}`} style={{fontSize:64,fontWeight:900,color,lineHeight:1}}>{result.threat_score}</div>
              </div>
              <span className={'badge-'+(result.severity||'low').toLowerCase()} style={{fontSize:12,padding:'6px 14px',marginBottom:4}}>{result.severity}</span>
            </div>
            <div className="score-bar"><div className="score-fill" style={{width:result.threat_score+'%',background:color,boxShadow:'0 0 8px '+color}}/></div>
            <div>
              <div className="label" style={{marginBottom:10}}>Source Breakdown</div>
              {Object.entries(result.raw_scores||{}).map(([src,score])=>(
                <div key={src} style={{display:'flex',alignItems:'center',gap:10,marginBottom:7}}>
                  <span style={{width:52,fontSize:10,color:'var(--gray2)',textTransform:'uppercase',fontWeight:700,fontFamily:"'Space Grotesk',sans-serif",letterSpacing:'.1em'}}>{src}</span>
                  <div className="score-bar" style={{flex:1}}><div className="score-fill" style={{width:(typeof score==='number'?score:0)+'%',background:color}}/></div>
                  <span className="mono" style={{fontSize:12,color,minWidth:36,textAlign:'right',fontWeight:600}}>{typeof score==='number'?score.toFixed(1):score}</span>
                </div>
              ))}
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
              {[['Country',result.country],['Type',result.ioc_type?.toUpperCase()]].map(([l,v])=>(
                <div key={l} style={{background:'var(--surface)',border:'1px solid var(--border2)',borderRadius:6,padding:'10px 12px'}}>
                  <div className="label" style={{marginBottom:5}}>{l}</div>
                  <div className="mono" style={{fontSize:13,color:'var(--white)',fontWeight:500}}>{v||'—'}</div>
                </div>
              ))}
            </div>
            {result.tags?.length>0&&(
              <div>
                <div className="label" style={{marginBottom:8}}>Indicators</div>
                <div style={{display:'flex',flexWrap:'wrap',gap:5}}>
                  {result.tags.slice(0,12).map((t,i)=><span key={i} className="badge-medium" style={{fontSize:10}}>{t}</span>)}
                </div>
              </div>
            )}
            {result.ai_summary&&(
              <div style={{background:'rgba(0,229,255,.04)',border:'1px solid rgba(0,229,255,.15)',borderLeft:'3px solid var(--cyan)',borderRadius:'0 8px 8px 0',padding:'14px 16px'}}>
                <div className="cyan-label" style={{marginBottom:10,fontSize:11}}>AI Analyst Briefing</div>
                <p style={{fontSize:13,color:'var(--white2)',lineHeight:1.8,fontFamily:"'Space Grotesk',sans-serif"}}>{result.ai_summary}</p>
              </div>
            )}
            {result.record_id&&(
              <a href={'http://localhost:8000/api/report/'+result.record_id} target="_blank" rel="noreferrer"
                className="ph-btn" style={{display:'block',textAlign:'center',textDecoration:'none',fontSize:11,padding:'10px'}}>
                EXPORT PDF REPORT
              </a>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
