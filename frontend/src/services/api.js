import axios from 'axios';
const BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';
export const api = {
  health:      ()                    => axios.get(`${BASE}/`),
  stats:       ()                    => axios.get(`${BASE}/api/stats`),
  feed:        (limit=20)            => axios.get(`${BASE}/api/feed?limit=${limit}`),
  threats:     (severity)            => axios.get(`${BASE}/api/threats${severity?`?severity=${severity}`:''}`),
  leaderboard: (limit=10)            => axios.get(`${BASE}/api/leaderboard?limit=${limit}`),
  analyze:     (ioc,type='ip',ai=true) => axios.get(`${BASE}/api/analyze/${ioc}?ioc_type=${type}&ai=${ai}`),
  fileHistory: ()                    => axios.get(`${BASE}/api/file-history?limit=30`),
};
export const getSeverityColor = s => ({ CRITICAL:'#FF1744',HIGH:'#FF6D00',MEDIUM:'#FFB300',LOW:'#00E676' }[s]||'#00E676');
export const getSeverityClass = s => ({ CRITICAL:'badge-critical',HIGH:'badge-high',MEDIUM:'badge-medium',LOW:'badge-low' }[s]||'badge-low');
export const createWebSocket = (onMessage, onConnect, onDisconnect) => {
  let ws=null, timer=null;
  const connect = () => {
    ws = new WebSocket('ws://localhost:8000/ws');
    ws.onopen  = () => { if(onConnect) onConnect(); };
    ws.onmessage = e => { try{ onMessage(JSON.parse(e.data)); }catch{} };
    ws.onerror = () => {};
    ws.onclose = () => { if(onDisconnect) onDisconnect(); timer=setTimeout(connect,3000); };
  };
  connect();
  return { close: () => { if(timer) clearTimeout(timer); if(ws) ws.close(); } };
};
