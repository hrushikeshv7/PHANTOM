import { useState, useRef } from 'react';
const BASE='http://localhost:8000';
const VC={MALICIOUS:'#FF1744',SUSPICIOUS:'#FF6D00','POTENTIALLY UNSAFE':'#FFB300',CLEAN:'#00E676'};
export default function FileAnalyzer(){
  const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false);
  const [error,setError]=useState(null);
  const [drag,setDrag]=useState(false);
  const ref=useRef();
  const analyze=async(file)=>{
    setLoading(true);setError(null);setResult(null);
    const form=new FormData();form.append('file',file);
    try{const res=await fetch(BASE+'/api/analyze-file?ai=true',{method:'POST',body:form});setResult(await res.json());}
    catch(e){setError('Connection failed.');}
    finally{setLoading(false);}
  };
  const color=result?(VC[result.verdict]||'#00E676'):'var(--cyan)';
  return(
    <div className="panel">
      <div className="panel-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FF1744" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span className="red-label" style={{fontSize:11}}>File Scanner</span>
        <span className="label" style={{marginLeft:'auto'}}>STATIC + AI</span>
      </div>
      <div style={{padding:'16px 18px'}}>
        <div onClick={()=>ref.current.click()}
          onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f)analyze(f);}}
          onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)}
          style={{border:'1px dashed '+(drag?'var(--cyan)':'var(--border2)'),borderRadius:8,padding:'28px 20px',textAlign:'center',cursor:'pointer',transition:'all .2s',background:drag?'rgba(0,229,255,.05)':'transparent',boxShadow:drag?'0 0 20px rgba(0,229,255,.1)':'none'}}>
          <input ref={ref} type="file" style={{display:'none'}} onChange={e=>e.target.files[0]&&analyze(e.target.files[0])}/>
          {loading
            ?<div className="orbitron" style={{color:'var(--cyan)',fontSize:13,letterSpacing:2}}>ANALYZING...</div>
            :<div>
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--gray2)" strokeWidth="1.5" style={{margin:'0 auto 12px',display:'block'}}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              <div style={{fontSize:14,color:'var(--white2)',fontFamily:"'Space Grotesk',sans-serif",fontWeight:500,marginBottom:4}}>Drop file or click to upload</div>
              <div style={{fontSize:11,color:'var(--gray2)'}}>Scripts · Executables · Source Code · Configs</div>
            </div>
          }
        </div>
        {error&&<div style={{marginTop:8,fontSize:12,color:'var(--red)'}}>{error}</div>}
      </div>
      {result&&(
        <div className="fade-up" style={{padding:'0 18px 18px',display:'flex',flexDirection:'column',gap:12}}>
          <div style={{display:'flex',alignItems:'flex-end',justifyContent:'space-between',padding:'14px 16px',background:color+'0d',border:'1px solid '+color+'25',borderLeft:'3px solid '+color,borderRadius:'0 8px 8px 0'}}>
            <div>
              <div className="orbitron" style={{fontSize:20,color,fontWeight:700,letterSpacing:2}}>{result.verdict}</div>
              <div className="mono" style={{fontSize:11,color:'var(--gray2)',marginTop:3}}>{result.filename}</div>
            </div>
            <div style={{textAlign:'right'}}>
              <div className="orbitron" style={{fontSize:44,color,lineHeight:1,fontWeight:900}}>{result.risk_score}</div>
              <div className="label" style={{marginTop:2}}>Risk Score</div>
            </div>
          </div>
          <div className="score-bar"><div className="score-fill" style={{width:result.risk_score+'%',background:color,boxShadow:'0 0 8px '+color}}/></div>
          {result.findings?.length>0&&(
            <div style={{background:'rgba(255,23,68,.05)',border:'1px solid rgba(255,23,68,.15)',borderRadius:6,padding:'12px 14px'}}>
              <div className="label" style={{color:'var(--red)',marginBottom:10}}>Detections ({result.findings.length})</div>
              {result.findings.map((f,i)=><div key={i} style={{fontSize:12,color:'var(--white2)',marginBottom:5,paddingLeft:12,borderLeft:'2px solid rgba(255,23,68,.3)',fontFamily:"'Space Grotesk',sans-serif",lineHeight:1.6}}>{f}</div>)}
            </div>
          )}
          {result.findings?.length===0&&<div style={{fontSize:13,color:'#00E676'}}>No malicious patterns detected</div>}
          {result.ai_analysis&&(
            <div style={{background:'rgba(255,23,68,.04)',borderLeft:'3px solid var(--red)',padding:'14px 16px',borderRadius:'0 8px 8px 0'}}>
              <div className="red-label" style={{marginBottom:10,fontSize:11}}>AI Deep Analysis</div>
              <pre style={{fontSize:11,color:'var(--white2)',fontFamily:"'JetBrains Mono',monospace",whiteSpace:'pre-wrap',lineHeight:1.8}}>{result.ai_analysis}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
