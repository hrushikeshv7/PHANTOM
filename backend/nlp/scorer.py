"""
PHANTØM — Upgraded Scoring Engine with NLP Boost
Composite score + NER entity boost + recency + CVE intelligence.
"""

from datetime import datetime, timezone

WEIGHTS = {
    "virustotal": 0.35,
    "abuseipdb":  0.30,
    "shodan":     0.20,
    "otx":        0.15,
}

SEVERITY_META = {
    "CRITICAL": {"color":"#FF1744","badge":"CRITICAL","priority":4},
    "HIGH":     {"color":"#FF6D00","badge":"HIGH",    "priority":3},
    "MEDIUM":   {"color":"#FFB300","badge":"MEDIUM",  "priority":2},
    "LOW":      {"color":"#00E676","badge":"LOW",     "priority":1},
}

CRITICAL_CVES = {
    "CVE-2021-44228","CVE-2021-41773","CVE-2022-30190",
    "CVE-2023-44487","CVE-2024-3400","CVE-2021-26084",
    "CVE-2021-34527","CVE-2020-1472","CVE-2019-19781",
}


def calculate_threat_score(aggregated: dict, nlp_entities: dict = None) -> dict:
    """
    Full intelligent threat scoring with NLP entity boost.
    """
    vt  = aggregated.get("virustotal", {})
    ab  = aggregated.get("abuseipdb",  {})
    sh  = aggregated.get("shodan",     {})
    ox  = aggregated.get("otx",        {})

    vt_score     = float(vt.get("vt_score",     0.0))
    abuse_score  = float(ab.get("abuse_score",  0.0))
    shodan_score = float(sh.get("shodan_score", 0.0))
    otx_score    = float(ox.get("otx_score",    0.0))

    # ── Base Score ─────────────────────────────────────
    base = (
        vt_score    * WEIGHTS["virustotal"] +
        abuse_score * WEIGHTS["abuseipdb"]  +
        shodan_score * WEIGHTS["shodan"]    +
        otx_score   * WEIGHTS["otx"]
    )

    boosts  = []
    penalty = 0

    # ── Whitelist ──────────────────────────────────────
    if ab.get("is_whitelisted"):
        base    = min(base, 8.0)
        penalty = 20
        boosts.append({"reason": "Whitelisted IP", "value": -20})

    # ── CVE Boost ──────────────────────────────────────
    cves              = sh.get("cves", [])
    critical_cve_hits = sum(1 for c in cves if c in CRITICAL_CVES)
    normal_cve_hits   = len(cves) - critical_cve_hits
    cve_boost         = min(critical_cve_hits * 14 + normal_cve_hits * 7, 42)
    if cve_boost:
        boosts.append({"reason": f"{len(cves)} CVEs found ({critical_cve_hits} critical)", "value": cve_boost})

    # ── Critical Port Boost ────────────────────────────
    critical_ports = sh.get("critical_ports", {})
    port_boost     = min(len(critical_ports) * 5, 25)
    if port_boost:
        boosts.append({"reason": f"{len(critical_ports)} critical ports open", "value": port_boost})

    # ── Recency Boost ──────────────────────────────────
    last_reported = ab.get("last_reported")
    if last_reported:
        try:
            last_dt  = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
            days_ago = (datetime.now(timezone.utc) - last_dt).days
            if days_ago <= 3:
                boosts.append({"reason": "Reported within 3 days", "value": 18})
            elif days_ago <= 7:
                boosts.append({"reason": "Reported within 7 days", "value": 12})
            elif days_ago <= 30:
                boosts.append({"reason": "Reported within 30 days", "value": 6})
        except Exception:
            pass

    # ── OTX Pulse Boost ────────────────────────────────
    pulse_count = ox.get("pulse_count", 0)
    if pulse_count >= 10:
        boosts.append({"reason": f"{pulse_count} active OTX pulses", "value": 15})
    elif pulse_count >= 5:
        boosts.append({"reason": f"{pulse_count} active OTX pulses", "value": 8})

    # ── Report Count Boost ─────────────────────────────
    total_reports = ab.get("total_reports", 0)
    if total_reports >= 200:
        boosts.append({"reason": f"{total_reports} abuse reports", "value": 12})
    elif total_reports >= 50:
        boosts.append({"reason": f"{total_reports} abuse reports", "value": 7})

    # ── Malware Family Boost ───────────────────────────
    malware_fams = ox.get("malware_families", [])
    if malware_fams:
        boost_val = min(len(malware_fams) * 8, 24)
        boosts.append({"reason": f"{len(malware_fams)} malware families", "value": boost_val})

    # ── NLP Entity Boost (Phase 3) ─────────────────────
    nlp_boost   = 0
    nlp_reasons = []
    if nlp_entities:
        from nlp.ner_engine import ner
        nlp_boost, nlp_reasons = ner.calculate_boost(nlp_entities)
        if nlp_boost > 0:
            for reason in nlp_reasons:
                boosts.append({"reason": f"[NLP] {reason}", "value": round(nlp_boost / max(len(nlp_reasons), 1), 1)})

    # ── Final Score ────────────────────────────────────
    total_boost = sum(b["value"] for b in boosts)
    final_score = round(min(max(base + total_boost - penalty, 0), 100), 2)
    severity    = _classify(final_score)
    meta        = SEVERITY_META[severity]

    # ── Geo ────────────────────────────────────────────
    country   = sh.get("country") or ab.get("country") or ox.get("country") or "Unknown"
    latitude  = sh.get("latitude")
    longitude = sh.get("longitude")

    # ── Tags ───────────────────────────────────────────
    tags = []
    for src in [vt, ox, ab, sh]:
        tags.extend(src.get("tags",       []))
        tags.extend(src.get("categories", []))

    # Add NLP-extracted entities as tags
    if nlp_entities:
        tags.extend(nlp_entities.get("threat_actors",  []))
        tags.extend(nlp_entities.get("malware",        []))
        tags.extend(nlp_entities.get("attack_types",   [])[:5])
        mitre = nlp_entities.get("mitre_techniques", [])
        tags.extend([t[0] for t in mitre[:5]])

    return {
        "ioc":          aggregated["ioc"],
        "ioc_type":     aggregated["ioc_type"],
        "threat_score": final_score,
        "severity":     severity,
        "color":        meta["color"],
        "badge":        meta["badge"],
        "priority":     meta["priority"],
        "country":      country,
        "latitude":     latitude,
        "longitude":    longitude,
        "tags":         list(dict.fromkeys(tags))[:25],
        "boosts":       boosts,
        "nlp_entities": nlp_entities or {},
        "raw_scores": {
            "vt":     vt_score,
            "abuse":  abuse_score,
            "shodan": shodan_score,
            "otx":    otx_score,
            "base":   round(base, 2),
            "final":  final_score,
        },
    }


def _classify(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def build_summary_context(aggregated, scored):
    vt = aggregated.get("virustotal", {})
    sh = aggregated.get("shodan",     {})
    ab = aggregated.get("abuseipdb",  {})
    ox = aggregated.get("otx",        {})
    ne = scored.get("nlp_entities",   {})

    return {
        "ioc":           scored["ioc"],
        "ioc_type":      scored["ioc_type"],
        "threat_score":  scored["threat_score"],
        "severity":      scored["severity"],
        "country":       scored.get("country", "Unknown"),
        "vt_positives":  vt.get("malicious",       0),
        "vt_total":      vt.get("total_engines",   0),
        "vt_label":      vt.get("raw_label",       "Unknown"),
        "vt_categories": ", ".join(vt.get("categories", [])[:3]) or "None",
        "open_ports":    ", ".join(str(p) for p in sh.get("open_ports", [])[:8]) or "None",
        "services":      ", ".join(sh.get("services",  [])[:3]) or "None",
        "cves":          ", ".join(sh.get("cves",      [])[:5]) or "None",
        "cve_count":     sh.get("cve_count", 0),
        "abuse_score":   ab.get("abuse_score",  0),
        "abuse_category":  ", ".join(ab.get("categories", [])[:3]) or "None",
        "total_reports": ab.get("total_reports", 0),
        "otx_pulses":    ox.get("pulse_count",  0),
        "otx_tags":      ", ".join(ox.get("tags",             [])[:5]) or "None",
        "malware_fams":  ", ".join(ox.get("malware_families", [])[:3]) or "None",
        "threat_actors": ", ".join(ne.get("threat_actors", [])[:3]) or "None",
        "nlp_malware":   ", ".join(ne.get("malware",       [])[:3]) or "None",
        "mitre_ids":     ", ".join(t[0] for t in ne.get("mitre_techniques", [])[:3]) or "None",
    }
