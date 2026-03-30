import { useEffect, useState } from 'react';
import StatCards    from './components/StatCards';
import ThreatFeed   from './components/ThreatFeed';
import IOCLookup    from './components/IOCLookup';
import ScoreBoard   from './components/ScoreBoard';
import ThreatChart  from './components/ThreatChart';
import AttackMap    from './components/AttackMap';
import FileAnalyzer from './components/FileAnalyzer';
import FileHistory  from './components/FileHistory';
import BulkScanner  from './components/BulkScanner';
import PhantomMark  from './components/GhostLogo';
import { api, createWebSocket } from './services/api';

const IC = {
  dash: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>,
  scan: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>,
  file: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  hist: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>,
  bulk: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  map:  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polygon points="3 11 22 2 13 21 11 13 3 11"/></svg>,
};
const NAV=[
  {id:'dashboard', label:'Overview',      icon:'dash'},
  {id:'analyze',   label:'IOC Analyzer',  icon:'scan'},
  {id:'files',     label:'File Scanner',  icon:'file'},
  {id:'filehistory',label:'File History', icon:'hist'},
  {id:'bulk',      label:'Bulk Scan',     icon:'bulk'},
  {id:'map',       label:'Attack Map',    icon:'map'},
];
const SUB={
  dashboard:'Real-time intelligence · VirusTotal · Shodan · AbuseIPDB · OTX · Groq AI',
  analyze:'Multi-source IOC analysis with AI-generated threat briefings',
  files:'Static pattern detection and AI-powered malicious code analysis',
  filehistory:'History of all analyzed files with AI verdicts and threat findings',
  bulk:'Upload a .txt file to scan up to 50 IOCs simultaneously',
  map:'Geographic distribution of all analyzed threat origins',
};
export default function App(){
  const [page,setPage]=useState('dashboard');
  const [online,setOnline]=useState(false);
  const [refresh,setRefresh]=useState(0);
  const [last,setLast]=useState(null);
  const [count,setCount]=useState(0);
  const [time,setTime]=useState(new Date());
  useEffect(()=>{api.health().then(()=>setOnline(true)).catch(()=>setOnline(false));},[]);
  useEffect(()=>{
    const ws=createWebSocket(d=>{if(d.type==='new_threat'){setLast(d);setRefresh(r=>r+1);setCount(c=>c+1);}},()=>{},()=>{});
    return()=>ws.close();
  },[]);
  useEffect(()=>{const t=setInterval(()=>setTime(new Date()),1000);return()=>clearInterval(t);},[]);
  return(
    <div style={{display:'flex',height:'100vh',overflow:'hidden',background:'var(--bg)'}}>
      <div className="scan-line"/>
      <aside style={{width:220,flexShrink:0,background:'var(--surface)',borderRight:'1px solid var(--border)',display:'flex',flexDirection:'column',padding:'20px 12px'}}>
        <div style={{display:'flex',alignItems:'center',gap:12,padding:'4px 8px',marginBottom:32}}>
          <PhantomMark size={34}/>
          <div>
            <div className="orbitron" style={{fontSize:18,fontWeight:900,color:'var(--white)',letterSpacing:3,lineHeight:1}}>PHANTØM</div>
            <div style={{fontSize:8,color:'var(--gray2)',letterSpacing:3,marginTop:4,fontFamily:"'Space Grotesk',sans-serif",fontWeight:700,textTransform:'uppercase'}}>Threat Intelligence</div>
          </div>
        </div>
        <div style={{fontSize:9,color:'var(--gray2)',letterSpacing:'.16em',textTransform:'uppercase',fontWeight:700,padding:'0 14px',marginBottom:8,fontFamily:"'Space Grotesk',sans-serif"}}>Navigation</div>
        <nav style={{display:'flex',flexDirection:'column',gap:3,flex:1}}>
          {NAV.map(n=>(
            <div key={n.id} className={'nav-item'+(page===n.id?' active':'')} onClick={()=>setPage(n.id)} style={{fontSize:13,fontWeight:500}}>
              {IC[n.icon]}{n.label}
            </div>
          ))}
        </nav>
        <div style={{borderTop:'1px solid var(--border)',paddingTop:16,display:'flex',flexDirection:'column',gap:10}}>
          <div style={{display:'flex',alignItems:'center',gap:8,padding:'0 6px'}}>
            <div style={{width:8,height:8,borderRadius:'50%',background:online?'var(--green)':'var(--red)',flexShrink:0,boxShadow:online?'0 0 8px var(--green)':'0 0 8px var(--red)'}} className="pulse-green"/>
            <span style={{fontSize:12,color:online?'var(--green)':'var(--red)',fontFamily:"'Space Grotesk',sans-serif",fontWeight:600}}>{online?'Connected':'Offline'}</span>
          </div>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'8px 10px',background:'rgba(0,229,255,.05)',border:'1px solid rgba(0,229,255,.1)',borderRadius:6}}>
            <span style={{fontSize:11,color:'var(--gray)'}}>Session Scans</span>
            <span className="orbitron" style={{fontSize:16,color:'var(--cyan)',fontWeight:700}}>{count}</span>
          </div>
          {last&&(
            <div style={{background:'rgba(255,23,68,.06)',border:'1px solid rgba(255,23,68,.2)',borderRadius:6,padding:'10px 12px'}}>
              <div className="orbitron" style={{fontSize:9,color:'var(--red)',letterSpacing:'.14em',marginBottom:5}}>LATEST ALERT</div>
              <div className="mono" style={{fontSize:11,color:'var(--white2)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{last.ioc}</div>
              <span className={'badge-'+(last.severity||'low').toLowerCase()} style={{fontSize:9,marginTop:5,display:'inline-block'}}>{last.severity}</span>
            </div>
          )}
          <div className="mono" style={{fontSize:10,color:'var(--gray2)',padding:'0 4px'}}>{time.toISOString().slice(0,19).replace('T',' ')} UTC</div>
        </div>
      </aside>
      <main style={{flex:1,overflowY:'auto',padding:20,display:'flex',flexDirection:'column'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:16}}>
          <div>
            <h1 className="orbitron" style={{fontSize:30,fontWeight:900,color:'var(--white)',letterSpacing:4,lineHeight:1}}>
              {NAV.find(n=>n.id===page)?.label?.toUpperCase()}
            </h1>
            <p style={{fontSize:12,color:'var(--gray2)',marginTop:6,fontFamily:"'Space Grotesk',sans-serif",letterSpacing:'.04em'}}>{SUB[page]}</p>
          </div>
          <div className="mono" style={{fontSize:10,color:'var(--gray2)',background:'var(--panel)',border:'1px solid var(--border)',borderRadius:4,padding:'6px 12px'}}>v3.0 · OPERATIONAL</div>
        </div>
        {page==='dashboard'&&(
          <div style={{display:'flex',flexDirection:'column',gap:12}}>
            <StatCards key={'s'+refresh}/>
            <div style={{display:'grid',gridTemplateColumns:'300px 1fr 280px',gap:12,height:540}}>
              <ThreatFeed/><IOCLookup onScanComplete={()=>setRefresh(r=>r+1)}/><ScoreBoard key={'b'+refresh}/>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
              <AttackMap key={'m'+refresh}/><ThreatChart key={'c'+refresh}/>
            </div>
          </div>
        )}
        {page==='analyze'&&(
          <div style={{display:'grid',gridTemplateColumns:'1fr 300px',gap:12,alignItems:'start'}}>
            <div style={{height:660}}><IOCLookup onScanComplete={()=>setRefresh(r=>r+1)}/></div>
            <div style={{display:'flex',flexDirection:'column',gap:12}}>
              <div style={{height:380}}><ScoreBoard key={'ba'+refresh}/></div>
              <ThreatChart key={'ca'+refresh}/>
            </div>
          </div>
        )}
        {page==='files'&&<div style={{maxWidth:780}}><FileAnalyzer/></div>}
        {page==='filehistory'&&<div style={{height:'calc(100vh - 140px)'}}><FileHistory/></div>}
        {page==='bulk'&&<div style={{maxWidth:780}}><BulkScanner onComplete={()=>setRefresh(r=>r+1)}/></div>}
        {page==='map'&&(
          <div style={{display:'flex',flexDirection:'column',gap:12}}>
            <AttackMap key={'mf'+refresh}/>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
              <ScoreBoard key={'bf'+refresh}/><ThreatChart key={'cf'+refresh}/>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
