"""
PHANTØM — AI Threat Briefing Generator (Phase 3 — NLP Enhanced)
Now includes MITRE ATT&CK techniques and extracted entities in prompts.
"""

from groq import Groq
import os
from dotenv import load_dotenv
from db.cache import cache

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

PROMPT = """You are a senior SOC analyst with 10+ years of experience. \
Write a professional threat briefing based on this intelligence data.

TARGET: {ioc} ({ioc_type}) | Country: {country}
RISK SCORE: {threat_score}/100 | Severity: {severity}

VIRUSTOTAL: {vt_positives}/{vt_total} engines flagged | Label: {vt_label} | Categories: {vt_categories}
SHODAN: Ports: {open_ports} | Services: {services} | CVEs: {cves} ({cve_count} total)
ABUSEIPDB: Score: {abuse_score}/100 | Attack Types: {abuse_category} | Reports: {total_reports}
OTX: Active Pulses: {otx_pulses} | Tags: {otx_tags} | Malware: {malware_fams}

NLP INTELLIGENCE (Phase 3):
- Threat Actors Identified: {threat_actors}
- Malware Families Detected: {nlp_malware}
- MITRE ATT&CK Techniques: {mitre_ids}

Write EXACTLY 3 sentences:
1. What is this threat and who is behind it? (use specific actor/malware names if found)
2. Why is it dangerous — what can it do and what is the potential impact?
3. What should the SOC team do RIGHT NOW?

Rules: Be direct. Reference real data. No vague language. Plain text only."""


async def generate_threat_briefing(context: dict) -> str:
    """Generate AI briefing with NLP-enhanced context."""
    cache_key = f"summary:{context['ioc']}"
    cached    = cache.get("ai_summary", cache_key)
    if cached:
        return cached.get("summary", "")

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=350,
            temperature=0.2,
            messages=[
                {"role": "system", "content": "You are a senior SOC analyst. Write precise, actionable threat intelligence briefings."},
                {"role": "user",   "content": PROMPT.format(**context)},
            ]
        )
        summary = response.choices[0].message.content.strip()
        cache.set("ai_summary", cache_key, {"summary": summary})
        return summary
    except Exception as e:
        return f"[AI briefing unavailable: {str(e)[:80]}]"
