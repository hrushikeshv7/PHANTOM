import { useState, useRef } from 'react';
import { getSeverityColor, getSeverityClass } from '../services/api';

const BASE = 'http://localhost:8000';

export default function BulkScanner({ onComplete }) {
  const [results,  setResults]  = useState(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState(null);
  const [progress, setProgress] = useState('');
  const [drag,     setDrag]     = useState(false);
  const fileRef = useRef();

  const scan = async (file) => {
    setLoading(true); setError(null); setResults(null);
    setProgress('Uploading and scanning ' + file.name + '...');
    const form = new FormData();
    form.append('file', file);
    try {
      const res  = await fetch(BASE + '/api/bulk-analyze?ioc_type=ip&ai=false', { method: 'POST', body: form });
      const data = await res.json();
      setResults(data);
      if (onComplete) onComplete();
    } catch (e) {
      setError('Bulk scan failed — check backend connection.');
    } finally {
      setLoading(false);
      setProgress('');
      fileRef.current.value = '';
    }
  };

  const onDrop = (e) => {
    e.preventDefault(); setDrag(false);
    const file = e.dataTransfer.files[0];
    if (file) scan(file);
  };

  const downloadCSV = () => {
    if (!results) return;
    const rows = results.results.map(r =>
      [r.ioc, r.threat_score, r.severity, r.country || 'Unknown'].join(',')
    );
    const csv  = 'IOC,Score,Severity,Country\n' + rows.join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'phantom_bulk_results.csv'; a.click();
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
        <span className="cyan-label" style={{ fontSize:11 }}>Bulk IOC Scanner</span>
        <span className="label" style={{ marginLeft:'auto' }}>MAX 50 IOCs</span>
      </div>

      <div style={{ padding:'16px 18px' }}>

        {/* Upload zone */}
        <div
          onClick={() => fileRef.current.click()}
          onDrop={onDrop}
          onDragOver={e => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          style={{
            border: '1px dashed ' + (drag ? 'var(--cyan)' : 'var(--border2)'),
            borderRadius: 8, padding: '32px 20px', textAlign: 'center',
            cursor: 'pointer', transition: 'all .2s',
            background: drag ? 'rgba(0,229,255,.05)' : 'transparent',
            boxShadow: drag ? '0 0 20px rgba(0,229,255,.1)' : 'none',
            marginBottom: 16,
          }}>
          <input ref={fileRef} type="file" accept=".txt" style={{ display:'none' }}
            onChange={e => e.target.files[0] && scan(e.target.files[0])} />

          {loading ? (
            <div>
              <div style={{ marginBottom: 12 }}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.5" style={{ margin:'0 auto', display:'block', animation:'spin 1s linear infinite' }}>
                  <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                </svg>
              </div>
              <div className="orbitron" style={{ color:'var(--cyan)', fontSize:12, letterSpacing:2 }}>
                {progress || 'SCANNING...'}
              </div>
            </div>
          ) : (
            <div>
              <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="var(--gray2)" strokeWidth="1.2" style={{ margin:'0 auto 12px', display:'block' }}>
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
              </svg>
              <div style={{ fontSize:14, color:'var(--white2)', fontFamily:"'Space Grotesk',sans-serif", fontWeight:500, marginBottom:6 }}>
                Drop .txt file or click to upload
              </div>
              <div style={{ fontSize:11, color:'var(--gray2)', fontFamily:"'Space Grotesk',sans-serif" }}>
                One IP per line · Maximum 50 IOCs per scan
              </div>
            </div>
          )}
        </div>

        {/* Format hint */}
        {!results && !loading && (
          <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:6, padding:'12px 14px' }}>
            <div className="label" style={{ marginBottom:8 }}>File Format Example</div>
            <pre className="mono" style={{ fontSize:11, color:'var(--gray)', lineHeight:1.8 }}>
{`185.220.101.45
8.8.8.8
45.33.32.156
198.199.10.234
194.165.16.11`}
            </pre>
          </div>
        )}

        {error && (
          <div style={{ fontSize:12, color:'var(--red)', fontFamily:"'Space Grotesk',sans-serif", marginTop:8 }}>
            {error}
          </div>
        )}
      </div>

      {/* Results */}
      {results && (
        <div style={{ padding:'0 18px 18px' }}>

          {/* Summary row */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8, marginBottom:12 }}>
            {[
              { label:'Total',    val: results.total,              color:'var(--cyan)'   },
              { label:'Critical', val: results.summary?.critical,  color:'#FF1744'       },
              { label:'High',     val: results.summary?.high,      color:'#FF6D00'       },
              { label:'Clean',    val: results.summary?.low,       color:'#00E676'       },
            ].map((s,i) => (
              <div key={i} style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:6, padding:'10px 12px', textAlign:'center' }}>
                <div className="orbitron" style={{ fontSize:22, fontWeight:700, color:s.color }}>{s.val}</div>
                <div className="label" style={{ fontSize:9, marginTop:3 }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Export button */}
          <button onClick={downloadCSV} className="ph-btn"
            style={{ width:'100%', marginBottom:12, display:'flex', alignItems:'center', justifyContent:'center', gap:8 }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            EXPORT CSV
          </button>

          {/* Results list */}
          <div style={{ maxHeight:400, overflowY:'auto', border:'1px solid var(--border)', borderRadius:6 }}>
            {results.results?.map((r, i) => {
              const color = r.severity === 'CRITICAL' ? '#FF1744' : r.severity === 'HIGH' ? '#FF6D00' : r.severity === 'MEDIUM' ? '#FFB300' : '#00E676';
              return (
                <div key={i}
                  style={{ display:'flex', alignItems:'center', gap:12, padding:'10px 14px', borderBottom:'1px solid var(--border)', transition:'background .12s' }}
                  onMouseEnter={e => e.currentTarget.style.background='rgba(255,255,255,.02)'}
                  onMouseLeave={e => e.currentTarget.style.background='transparent'}>

                  {/* Rank */}
                  <span className="orbitron" style={{ fontSize:12, color:'var(--gray2)', width:24, flexShrink:0 }}>
                    {i + 1}
                  </span>

                  {/* IOC */}
                  <div style={{ flex:1, minWidth:0 }}>
                    <div className="mono" style={{ fontSize:12, color:'var(--white2)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {r.ioc}
                    </div>
                    <div style={{ fontSize:10, color:'var(--gray2)', marginTop:2, fontFamily:"'Space Grotesk',sans-serif" }}>
                      {r.country || 'Unknown'} · {r.ioc_type || 'ip'}
                    </div>
                  </div>

                  {/* Score bar */}
                  <div style={{ width:80 }}>
                    <div style={{ height:2, background:'var(--border)', borderRadius:1, overflow:'hidden' }}>
                      <div style={{ height:'100%', width:(r.threat_score||0)+'%', background:color, borderRadius:1 }}/>
                    </div>
                  </div>

                  {/* Score + badge */}
                  <div style={{ textAlign:'right', flexShrink:0 }}>
                    <div className="orbitron" style={{ fontSize:15, fontWeight:700, color }}>{r.threat_score?.toFixed(1)}</div>
                    <span className={'badge-'+(r.severity||'low').toLowerCase()} style={{ fontSize:9 }}>{r.severity}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Spin keyframe */}
      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}
