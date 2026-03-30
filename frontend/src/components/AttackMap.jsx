import { useEffect, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import { api } from '../services/api';
import 'leaflet/dist/leaflet.css';
const SC={CRITICAL:'#FF1744',HIGH:'#FF6D00',MEDIUM:'#FFB300',LOW:'#00E676'};
export default function AttackMap(){
  const [threats,setThreats]=useState([]);
  useEffect(()=>{
    api.threats().then(r=>{
      setThreats(r.data.threats.filter(t=>t.latitude!=null&&t.longitude!=null&&!isNaN(Number(t.latitude))&&!isNaN(Number(t.longitude))));
    }).catch(()=>{});
  },[]);
  return(
    <div className="panel" style={{overflow:'hidden'}}>
      <div className="panel-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2"><polygon points="3 11 22 2 13 21 11 13 3 11"/></svg>
        <span className="cyan-label" style={{fontSize:11}}>Origin Map</span>
        <span className="label" style={{marginLeft:'auto'}}>{threats.length} TRACKED</span>
      </div>
      <MapContainer center={[20,0]} zoom={2} style={{height:270,width:'100%'}} zoomControl={false} attributionControl={false}>
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"/>
        {threats.map((t,i)=>(
          <CircleMarker key={i} center={[Number(t.latitude),Number(t.longitude)]}
            radius={t.severity==='CRITICAL'?9:t.severity==='HIGH'?7:t.severity==='MEDIUM'?5:4}
            pathOptions={{color:SC[t.severity]||'#00E676',fillColor:SC[t.severity]||'#00E676',fillOpacity:.75,weight:1.5}}>
            <Popup>
              <div style={{fontSize:12,fontFamily:"'Space Grotesk',sans-serif"}}>
                <div style={{fontWeight:700,color:SC[t.severity],marginBottom:3,fontFamily:"'Orbitron',sans-serif",fontSize:11}}>{t.severity}</div>
                <div className="mono" style={{fontSize:11}}>{t.ioc}</div>
                <div style={{color:'var(--gray)',marginTop:2}}>{t.country}</div>
                <div style={{color:'var(--cyan)',fontWeight:600,marginTop:2}}>Score: {t.threat_score?.toFixed(1)}</div>
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}
