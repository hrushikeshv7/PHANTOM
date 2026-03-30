"""
PHANTØM — File/Code Malware Analyzer
Uses Groq AI to analyze uploaded files for malicious patterns.
Combines static analysis + AI reasoning.
"""

import hashlib
import re
from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Known malicious patterns
MALICIOUS_PATTERNS = {
    "reverse_shell":    [r"bash\s+-i", r"/dev/tcp/", r"nc\s+-e", r"mkfifo", r"0>&1"],
    "privilege_escalation": [r"sudo\s+su", r"chmod\s+[0-9]*s", r"/etc/passwd", r"suid"],
    "data_exfiltration": [r"curl\s+.*POST", r"wget\s+.*upload", r"base64.*decode", r"xxd\s+-r"],
    "persistence":      [r"crontab", r"systemctl\s+enable", r"~/.bashrc", r"/etc/rc"],
    "obfuscation":      [r"eval\(base64", r"exec\(base64", r"\\x[0-9a-f]{2}", r"chr\([0-9]+\)\*"],
    "crypto_mining":    [r"xmrig", r"stratum\+tcp", r"monero", r"--mining"],
    "sql_injection":    [r"UNION\s+SELECT", r"DROP\s+TABLE", r"'.*OR.*'.*=.*'", r"1=1"],
    "xss":             [r"<script>alert", r"javascript:void", r"onerror=", r"onload="],
    "ransomware":       [r"AES.*encrypt", r"RSA.*encrypt", r"\.encrypt\(", r"ransom"],
    "keylogger":        [r"GetAsyncKeyState", r"SetWindowsHookEx", r"keylogger", r"keyboard.*hook"],
}

SAFE_EXTENSIONS = {'.txt', '.md', '.csv', '.json', '.yaml', '.yml', '.xml', '.html', '.css'}
RISKY_EXTENSIONS = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.sh', '.py', '.js', '.php', '.rb'}


def analyze_file_static(filename: str, content: str) -> dict:
    """Static pattern-based malware detection."""
    findings = []
    risk_score = 0

    ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    # Extension risk
    if ext in RISKY_EXTENSIONS:
        risk_score += 10
        findings.append(f"Risky file extension: {ext}")

    # Pattern matching
    for category, patterns in MALICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                risk_score += 15
                findings.append(f"{category.replace('_', ' ').title()} pattern detected: `{pattern}`")
                break

    # Entropy check (high entropy = possible obfuscation)
    if len(content) > 100:
        entropy = _calculate_entropy(content[:1000])
        if entropy > 5.5:
            risk_score += 10
            findings.append(f"High entropy detected ({entropy:.2f}) — possible obfuscation or encryption")

    # Suspicious strings
    suspicious = ["HKEY_", "RegOpenKey", "VirtualAlloc", "CreateRemoteThread",
                  "WinExec", "ShellExecute", "DownloadString", "IEX", "Invoke-Expression"]
    for s in suspicious:
        if s.lower() in content.lower():
            risk_score += 8
            findings.append(f"Suspicious API call: `{s}`")

    return {
        "risk_score":    min(risk_score, 100),
        "findings":      findings,
        "extension":     ext,
        "file_size":     len(content),
        "line_count":    content.count('\n'),
        "sha256":        hashlib.sha256(content.encode()).hexdigest(),
    }


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    import math
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((f/length) * math.log2(f/length) for f in freq.values())


async def analyze_file_ai(filename: str, content: str, static_results: dict) -> str:
    """AI-powered deep analysis using Groq."""
    truncated = content[:3000]

    findings_str = "\n".join(f"- {f}" for f in static_results["findings"]) or "None detected"

    prompt = f"""You are a senior malware analyst. Analyze this file for security threats.

FILE INFO:
- Name: {filename}
- Extension: {static_results['extension']}
- Size: {static_results['file_size']} bytes
- Lines: {static_results['line_count']}
- SHA256: {static_results['sha256']}
- Static Risk Score: {static_results['risk_score']}/100

STATIC ANALYSIS FINDINGS:
{findings_str}

FILE CONTENT (first 3000 chars):
```
{truncated}
```

Provide a security analysis in exactly 4 sections:
1. VERDICT: [MALICIOUS/SUSPICIOUS/CLEAN] — one word verdict with confidence %
2. THREAT TYPE: What kind of malware or attack is this? (if any)
3. ANALYSIS: 2-3 sentences explaining what this code does and why it is or isn't dangerous
4. RECOMMENDATION: Exactly what the analyst should do next

Be specific. Reference actual code patterns you see. Be direct."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=400,
            temperature=0.1,
            messages=[
                {"role": "system", "content": "You are a malware analyst. Be precise and technical."},
                {"role": "user",   "content": prompt}
            ]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI analysis unavailable: {str(e)[:80]}"


def get_verdict_severity(risk_score: int) -> tuple:
    """Convert risk score to verdict and severity."""
    if risk_score >= 70:
        return "MALICIOUS",   "CRITICAL", "#FF2D2D"
    elif risk_score >= 40:
        return "SUSPICIOUS",  "HIGH",     "#FF6B00"
    elif risk_score >= 15:
        return "POTENTIALLY UNSAFE", "MEDIUM", "#FFD700"
    else:
        return "CLEAN",       "LOW",      "#00FF88"
