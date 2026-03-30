<div align="center">

# PHANTØM
### Proactive Heuristic Analytics & NLP Threat Orchestration Monitor

**A production-grade AI-powered SOC Threat Intelligence Platform**

[![Status](https://img.shields.io/badge/Status-Production%20Ready-00E676?style=for-the-badge)](https://github.com/hrushikeshv7/PHANTOM)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [API Docs](#-api-endpoints) · [Screenshots](#-dashboard)

</div>

---

## 🔍 What is PHANTØM?

PHANTØM is a full-stack threat intelligence platform built for Security Operations Center (SOC) teams. It aggregates real-time data from **4 industry-leading threat feeds**, processes it through a **custom NLP scoring engine with MITRE ATT&CK mapping**, and delivers **AI-generated analyst briefings** — all on a live interactive dashboard.

> Built by a single engineer. Runs like an enterprise product.

---

## ✨ Features

### Core Intelligence
- **Multi-Source Aggregation** — Concurrent async fetching from VirusTotal, Shodan, AbuseIPDB, AlienVault OTX (4x faster than sequential)
- **Composite Threat Scoring** — Weighted 0–100 score with CVE severity boosts, recency scoring, OTX pulse amplification, and whitelist penalties
- **NLP Entity Extraction** — Identifies threat actors (APT28, Lazarus Group), malware families (Emotet, Ryuk), and CVE IDs from raw text
- **MITRE ATT&CK Mapping** — Auto-maps extracted entities to technique IDs (T1566, T1110, T1486...)
- **AI Analyst Briefings** — Groq Llama3-70B generates 3-sentence SOC-grade summaries per IOC, referencing actual extracted entities

### Dashboard Panels
- 📡 **Live Threat Feed** — Real-time OTX global threat pulses with click-to-expand details
- 🔍 **IOC Analyzer** — Submit any IP/domain/hash for instant multi-source analysis
- 🌍 **Attack Origin Map** — Leaflet.js geo-map of all analyzed threat origins
- 🏆 **Top Threats Leaderboard** — Live-ranked threats with WebSocket updates
- 📊 **Score History Chart** — Recharts bar chart of last 20 analyses
- 🛡️ **File Malware Analyzer** — Static pattern detection + AI deep analysis on uploaded files
- 📋 **File Analysis History** — Searchable history of all analyzed files with AI verdicts
- 📦 **Bulk IOC Scanner** — Upload .txt → scan 50 IPs concurrently with CSV export

### Operations
- 📄 **PDF Report Generator** — Professional SOC-grade PDF per analyzed IOC (ReportLab)
- 🔔 **Real-Time Alerting** — Slack + email auto-notifications on CRITICAL detections
- ⚡ **WebSocket Live Updates** — Dashboard updates instantly without page refresh
- 📱 **Mobile Responsive** — Bottom-nav mobile layout for on-call SOC access
- 🗄️ **Persistent Storage** — PostgreSQL for history + Redis for API response caching

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  FRONTEND  (React 18 + Tailwind CSS)              │
│  Overview │ IOC Analyzer │ File Scanner │ Bulk Scan │ Attack Map  │
└─────────────────────────┬────────────────────────────────────────┘
                          │  REST API + WebSocket
┌─────────────────────────▼────────────────────────────────────────┐
│                  BACKEND  (FastAPI + Python 3.11)                 │
│                                                                    │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────┐ │
│  │  API Layer  │   │  NLP Engine  │   │   Groq AI Summarizer  │ │
│  │  asyncio    │   │  SecBERT NER │   │   Llama3-70B          │ │
│  └──────┬──────┘   └──────┬───────┘   └───────────┬───────────┘ │
└─────────│────────────────│───────────────────────│──────────────┘
          │                │                       │
   4 Sources            Score 0-100           PostgreSQL
   concurrently         MITRE Map             + Redis
   via asyncio          NLP Boost             Cache
```

### NLP Pipeline (Phase 3)

```
Raw threat text from OTX + API responses
          │
          ▼
  Named Entity Recognition
  ├── Threat Actors  →  APT28, Lazarus, FIN7
  ├── Malware Names  →  Emotet, Ryuk, Cobalt Strike
  ├── CVE IDs        →  CVE-2021-44228
  └── Attack Types   →  ransomware, botnet, c2
          │
          ▼
  MITRE ATT&CK Mapping
  ├── "phishing"     →  T1566
  ├── "ransomware"   →  T1486
  └── "brute force"  →  T1110
          │
          ▼
  Composite Score + NLP Entity Boost
  Base  = VT×0.35 + AbuseIPDB×0.30 + Shodan×0.20 + OTX×0.15
  Boost = +18 (threat actor) +15 (malware) +12 (CVE)
  Final = min(Base + Boost, 100)
          │
          ▼
  Groq AI Analyst Briefing
  3-sentence SOC report with real entity references
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **API Framework** | FastAPI | Async REST + WebSocket server |
| **Async HTTP** | httpx + asyncio | 4 concurrent API calls |
| **NLP** | HuggingFace + regex | Threat entity extraction |
| **AI** | Groq (Llama3-70B) | SOC analyst briefings |
| **Database** | PostgreSQL + SQLAlchemy | Threat + file history |
| **Cache** | Redis | API rate limit protection |
| **PDF** | ReportLab | Threat report generation |
| **Frontend** | React 18 | UI framework |
| **Styling** | Tailwind CSS + Orbitron | Cybersec design system |
| **Charts** | Recharts | Score history visualization |
| **Maps** | Leaflet.js | Attack origin geo-map |
| **Fonts** | Orbitron + Space Grotesk + JetBrains Mono | Typography |
| **Deployment** | Docker + Render | Containerized cloud deploy |

---

## 📁 Project Structure

```
PHANTOM/
├── .env.example                 ← Environment variable template
├── docker-compose.yml           ← Full stack Docker config
│
├── backend/
│   ├── main.py                  ← FastAPI app + all 10 endpoints
│   ├── requirements.txt
│   ├── api/
│   │   ├── virustotal.py        ← VirusTotal async client
│   │   ├── shodan.py            ← Shodan async client
│   │   ├── abuseipdb.py         ← AbuseIPDB async client
│   │   └── otx.py               ← AlienVault OTX async client
│   ├── nlp/
│   │   ├── ner_engine.py        ← NER + MITRE ATT&CK mapping
│   │   ├── scorer.py            ← Composite threat scoring
│   │   └── summarizer.py        ← Groq AI briefing generator
│   ├── db/
│   │   ├── models.py            ← SQLAlchemy models
│   │   ├── database.py          ← DB connection
│   │   └── cache.py             ← Redis caching layer
│   └── utils/
│       ├── aggregator.py        ← Async multi-source fetcher
│       ├── alerts.py            ← Slack + email alerting
│       ├── file_analyzer.py     ← Static + AI malware analysis
│       ├── helpers.py           ← IP geolocation fallback
│       └── pdf_report.py        ← PDF report generator
│
└── frontend/
    └── src/
        ├── App.jsx              ← Main layout + sidebar navigation
        ├── index.css            ← Global styles + animations
        ├── services/api.js      ← API client + WebSocket
        └── components/
            ├── StatCards.jsx
            ├── ThreatFeed.jsx
            ├── IOCLookup.jsx
            ├── ScoreBoard.jsx
            ├── ThreatChart.jsx
            ├── AttackMap.jsx
            ├── FileAnalyzer.jsx
            ├── FileHistory.jsx
            ├── BulkScanner.jsx
            └── GhostLogo.jsx
```

---

## 🚀 Quick Start

### Prerequisites
```
Python 3.11+    Node.js 18+    PostgreSQL    Redis
```

### 1. Clone & Configure

```bash
git clone https://github.com/hrushikeshv7/PHANTOM.git
cd PHANTOM
cp .env.example .env
# Edit .env with your API keys
```

### 2. Backend Setup

```bash
cd backend
python3 -m venv phantom_env
source phantom_env/bin/activate
pip install -r requirements.txt

# Database setup
sudo systemctl start postgresql redis-server
sudo -u postgres psql << 'SQL'
CREATE DATABASE phantom_db;
CREATE USER phantom_user WITH PASSWORD 'phantom_pass_2024';
GRANT ALL PRIVILEGES ON DATABASE phantom_db TO phantom_user;
\c phantom_db
GRANT ALL ON SCHEMA public TO phantom_user;
SQL

python main.py
# Running at http://localhost:8000
# API docs at http://localhost:8000/docs
```

### 3. Frontend Setup

```bash
cd frontend
npm install
npm start
# Dashboard at http://localhost:3000
```

### 4. Docker (one command)

```bash
docker-compose up --build
# Dashboard at http://localhost:3000
```

---

## 🔑 Environment Variables

```env
# Threat Intelligence (all free tiers)
VIRUSTOTAL_API_KEY=     # virustotal.com       — 500 req/day
SHODAN_API_KEY=         # shodan.io            — 100 req/month
ABUSEIPDB_API_KEY=      # abuseipdb.com        — 1000 req/day
OTX_API_KEY=            # otx.alienvault.com   — unlimited

# AI (free)
GROQ_API_KEY=           # console.groq.com     — free tier

# Alerts (optional)
SLACK_WEBHOOK_URL=      # api.slack.com
ALERT_THRESHOLD=60      # Auto-alert above this score

# Infrastructure
DATABASE_URL=postgresql://phantom_user:phantom_pass_2024@localhost/phantom_db
REDIS_URL=redis://localhost:6379
CORS_ORIGINS=http://localhost:3000
APP_PORT=8000
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/analyze/{ioc}` | Full multi-source IOC analysis with AI briefing |
| `GET` | `/api/feed` | Live OTX threat pulses |
| `GET` | `/api/threats` | Historical threat records |
| `GET` | `/api/leaderboard` | Top threats ranked by composite score |
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/api/report/{id}` | Download PDF threat report |
| `POST` | `/api/bulk-analyze` | Bulk IOC scan (upload .txt, max 50) |
| `POST` | `/api/analyze-file` | File malware analysis |
| `GET` | `/api/file-history` | File analysis history |
| `WS` | `/ws` | WebSocket live updates |

---

## 🌐 Data Sources

| Source | What it provides | Free Limit |
|---|---|---|
| [VirusTotal](https://virustotal.com) | Malware verdicts from 70+ AV engines | 500/day |
| [Shodan](https://shodan.io) | Open ports, CVEs, running services | 100/month |
| [AbuseIPDB](https://abuseipdb.com) | Community abuse confidence scores | 1000/day |
| [AlienVault OTX](https://otx.alienvault.com) | Global threat pulses and IOC feeds | Unlimited |

---

## ✅ Build Phases

| Phase | Description | Status |
|---|---|---|
| Phase 1 | Environment setup + project structure | ✅ Complete |
| Phase 2 | 4 async API integrations + FastAPI backend | ✅ Complete |
| Phase 3 | NLP engine — SecBERT NER + MITRE ATT&CK | ✅ Complete |
| Phase 4 | Groq AI analyst briefing generator | ✅ Complete |
| Phase 5 | React frontend — 6 live dashboard panels | ✅ Complete |
| Phase 6 | Docker containerization + Render deployment | ✅ Complete |
| Tier 1 | Alerting + Bulk Scanner + PDF Reports + File Analyzer | ✅ Complete |
| UI v3 | Premium cybersec design (Orbitron + Space Grotesk) | ✅ Complete |
| Phase 3+ | File history feed + Mobile responsive layout | ✅ Complete |

---

## 🏆 Why PHANTØM?

Most threat intelligence tools require expensive subscriptions or complex enterprise setups. PHANTØM demonstrates that a single engineer can build a production-grade SOC platform from scratch using free APIs, open-source models, and modern web tooling.

**What makes it different:**
- Correlates 4 sources simultaneously — most tools check one at a time
- NLP extracts real threat actor names and maps them to MITRE ATT&CK — not just raw API scores
- AI writes the analyst report for you — not a template, a real briefing
- Built to be understood — every component is documented and readable

---

## 👨‍💻 Author

**Korapothula Hrushikesh Vardhan**
Cybersecurity Engineer · IIT Kharagpur · CEH v12 Certified

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/hrushikesh-vardhan-975a5b29a)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github)](https://github.com/hrushikeshv7)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*"The phantom watches silently. The threat never sees it coming."*

**⭐ Star this repo if PHANTØM helped you**

</div>
