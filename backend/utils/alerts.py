"""
PHANTØM — Real-Time Alert System
Sends Slack notifications when threats exceed threshold.
Supports: Slack webhook, Email (SMTP)
"""

import httpx
import smtplib
import os
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK_URL")
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", 60))
SMTP_HOST       = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT", 587))
SMTP_USER       = os.getenv("SMTP_USER")
SMTP_PASS       = os.getenv("SMTP_PASS")
ALERT_EMAIL     = os.getenv("ALERT_EMAIL")

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

SEVERITY_COLOR = {
    "CRITICAL": "#FF2D2D",
    "HIGH":     "#FF6B00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00FF88",
}


async def send_alert(threat_data: dict):
    """
    Fire alerts if threat score exceeds threshold.
    Sends to Slack and/or email based on .env config.
    """
    score    = threat_data.get("threat_score", 0)
    severity = threat_data.get("severity", "LOW")

    if score < ALERT_THRESHOLD:
        return  # Below threshold — no alert

    # Fire both concurrently
    import asyncio
    tasks = []
    if SLACK_WEBHOOK:
        tasks.append(_send_slack(threat_data))
    if SMTP_USER and ALERT_EMAIL:
        tasks.append(_send_email(threat_data))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _send_slack(data: dict):
    """Send rich Slack notification."""
    score    = data.get("threat_score", 0)
    severity = data.get("severity", "LOW")
    ioc      = data.get("ioc", "Unknown")
    country  = data.get("country", "Unknown")
    summary  = data.get("ai_summary", "No summary available.")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")
    color    = SEVERITY_COLOR.get(severity, "#888888")

    payload = {
        "text": f"{emoji} *PHANTØM ALERT — {severity} THREAT DETECTED*",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*IOC:*\n`{ioc}`"},
                            {"type": "mrkdwn", "text": f"*Score:*\n{score}/100"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{emoji} {severity}"},
                            {"type": "mrkdwn", "text": f"*Country:*\n{country}"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*AI Analyst Briefing:*\n_{summary[:300]}_"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "🔍 View in PHANTØM"},
                                "url":  "http://localhost:3000",
                                "style": "danger"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        await client.post(SLACK_WEBHOOK, json=payload)


async def _send_email(data: dict):
    """Send email alert via SMTP."""
    score    = data.get("threat_score", 0)
    severity = data.get("severity", "LOW")
    ioc      = data.get("ioc", "Unknown")
    summary  = data.get("ai_summary", "No summary available.")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    subject = f"{emoji} PHANTØM ALERT — {severity}: {ioc} scored {score}/100"

    html = f"""
    <div style="font-family:monospace;background:#080810;color:#c8c8e8;padding:20px;border-radius:8px;">
        <h2 style="color:#FF2D2D;">🛡️ PHANTØM THREAT ALERT</h2>
        <table style="width:100%;border-collapse:collapse;">
            <tr>
                <td style="padding:8px;color:#4a4a6a;">IOC</td>
                <td style="padding:8px;color:#00D4FF;">{ioc}</td>
            </tr>
            <tr>
                <td style="padding:8px;color:#4a4a6a;">Score</td>
                <td style="padding:8px;color:#FF2D2D;font-size:24px;font-weight:bold;">{score}/100</td>
            </tr>
            <tr>
                <td style="padding:8px;color:#4a4a6a;">Severity</td>
                <td style="padding:8px;">{emoji} {severity}</td>
            </tr>
            <tr>
                <td style="padding:8px;color:#4a4a6a;">Country</td>
                <td style="padding:8px;">{data.get('country','Unknown')}</td>
            </tr>
        </table>
        <div style="margin-top:16px;padding:12px;background:#0d0d1a;border-left:3px solid #FF2D2D;border-radius:4px;">
            <strong style="color:#00D4FF;">AI Analyst Briefing:</strong>
            <p style="margin-top:8px;line-height:1.6;">{summary}</p>
        </div>
        <p style="margin-top:16px;color:#4a4a6a;font-size:12px;">
            Generated by PHANTØM Threat Intelligence Platform
        </p>
    </div>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = ALERT_EMAIL
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())
    except Exception as e:
        print(f"Email alert failed: {e}")
