"""Real-time dashboard statistics, computed from the SQLite database.

Every endpoint here queries the `scans` table live -- nothing is
hardcoded. All data is aggregate/anonymous: no endpoint exposes which
individual user made a given scan (see /api/admin/users in app.py for the
one place per-account scan *counts* are shown, which is already
owner-gated).

Endpoints (all require the 'owner' role, see auth.require_role):
  GET /api/stats/scans        -> scan counts for day / week / month
  GET /api/stats/threat-rate  -> detection rate (threats / total scans)
  GET /api/stats/timeline     -> per-day scan/threat counts, last N days
  GET /api/stats/services     -> live health-check of external services
"""
import os
import smtplib
import time
from datetime import datetime, timedelta

import requests
from flask import Blueprint, current_app, jsonify, request

from auth import require_role
from db import get_db

stats_bp = Blueprint("stats", __name__, url_prefix="/api/stats")

# Kept in sync with the definition used by the existing /api/stats endpoint
# in app.py, so "threat rate" means the same thing everywhere in the app.
THREAT_CATEGORIES = ("Phishing", "Social Engineering", "Image Phishing", "Alert")

REQUEST_TIMEOUT = 4  # seconds, for outbound health-check calls


def _iso(dt):
    return dt.isoformat()


@stats_bp.route("/scans")
@require_role(["owner"])
def scans_by_period():
    """Real scan counts for the last day / 7 days / 30 days."""
    db = get_db()
    now = datetime.utcnow()
    windows = {
        "day": now - timedelta(days=1),
        "week": now - timedelta(days=7),
        "month": now - timedelta(days=30),
    }
    counts = {}
    for label, cutoff in windows.items():
        row = db.execute(
            "SELECT COUNT(*) FROM scans WHERE created_at >= ?", (_iso(cutoff),)
        ).fetchone()
        counts[label] = row[0]

    return jsonify({"success": True, "scans": counts, "generated_at": _iso(now)})


@stats_bp.route("/threat-rate")
@require_role(["owner"])
def threat_rate():
    """Ratio of scans flagged as a threat over total scans, in DB."""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    placeholders = ", ".join("?" for _ in THREAT_CATEGORIES)
    threats = db.execute(
        f"SELECT COUNT(*) FROM scans WHERE category IN ({placeholders})",
        THREAT_CATEGORIES,
    ).fetchone()[0]
    rate = round((threats / total) * 100, 1) if total else 0.0

    return jsonify(
        {
            "success": True,
            "total_scans": total,
            "threat_scans": threats,
            "detection_rate": rate,
        }
    )


@stats_bp.route("/timeline")
@require_role(["owner"])
def threats_timeline():
    """Daily scan/threat counts for the last N days (default 30), for the chart."""
    days = request.args.get("days", default=30, type=int)
    days = max(1, min(days, 90))

    db = get_db()
    now = datetime.utcnow()
    start = now - timedelta(days=days - 1)
    placeholders = ", ".join("?" for _ in THREAT_CATEGORIES)

    rows = db.execute(
        f"""
        SELECT substr(created_at, 1, 10) AS day,
               COUNT(*) AS total,
               SUM(CASE WHEN category IN ({placeholders}) THEN 1 ELSE 0 END) AS threats
        FROM scans
        WHERE created_at >= ?
        GROUP BY day
        ORDER BY day ASC
        """,
        (*THREAT_CATEGORIES, _iso(start)),
    ).fetchall()
    by_day = {row["day"]: (row["total"], row["threats"] or 0) for row in rows}

    labels, scans_series, threats_series = [], [], []
    for offset in range(days):
        day_str = (start + timedelta(days=offset)).date().isoformat()
        total, threats = by_day.get(day_str, (0, 0))
        labels.append(day_str)
        scans_series.append(total)
        threats_series.append(threats)

    return jsonify(
        {
            "success": True,
            "labels": labels,
            "scans": scans_series,
            "threats": threats_series,
        }
    )


def _check_clerk():
    secret = os.environ.get("CLERK_SECRET_KEY", "")
    if not secret:
        return {"name": "Clerk Authentication", "status": "not_configured"}
    started = time.monotonic()
    try:
        resp = requests.get(
            "https://api.clerk.com/v1/users/count",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=REQUEST_TIMEOUT,
        )
        latency_ms = round((time.monotonic() - started) * 1000)
        if resp.status_code == 200:
            status = "online" if latency_ms < 1500 else "degraded"
        else:
            status = "offline"
        return {
            "name": "Clerk Authentication",
            "status": status,
            "latency_ms": latency_ms,
            "http_status": resp.status_code,
        }
    except requests.RequestException as exc:
        current_app.logger.warning("Clerk health check failed: %s", exc)
        return {"name": "Clerk Authentication", "status": "offline", "error": str(exc)}


def _check_virustotal():
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"name": "VirusTotal", "status": "not_configured"}
    started = time.monotonic()
    try:
        # Account-info lookup does not consume scan/lookup quota.
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/users/{api_key}",
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        latency_ms = round((time.monotonic() - started) * 1000)
        if resp.status_code == 200:
            status = "online"
        elif resp.status_code == 429:
            status = "degraded"
        else:
            status = "offline"
        return {
            "name": "VirusTotal",
            "status": status,
            "latency_ms": latency_ms,
            "http_status": resp.status_code,
        }
    except requests.RequestException as exc:
        current_app.logger.warning("VirusTotal health check failed: %s", exc)
        return {"name": "VirusTotal", "status": "offline", "error": str(exc)}


def _check_safe_browsing():
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        return {"name": "Google Safe Browsing", "status": "not_configured"}
    started = time.monotonic()
    body = {
        "client": {"clientId": "cyberguard-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "http://example.com"}],
        },
    }
    try:
        resp = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": api_key},
            json=body,
            timeout=REQUEST_TIMEOUT,
        )
        latency_ms = round((time.monotonic() - started) * 1000)
        status = "online" if resp.status_code == 200 else "offline"
        return {
            "name": "Google Safe Browsing",
            "status": status,
            "latency_ms": latency_ms,
            "http_status": resp.status_code,
        }
    except requests.RequestException as exc:
        current_app.logger.warning("Safe Browsing health check failed: %s", exc)
        return {"name": "Google Safe Browsing", "status": "offline", "error": str(exc)}


def _check_mail_server():
    host = os.environ.get("MAIL_SERVER")
    if not host:
        return {"name": "Mail Server (SMTP)", "status": "not_configured"}
    port = int(os.environ.get("MAIL_PORT", 587) or 587)
    started = time.monotonic()
    try:
        with smtplib.SMTP(host, port, timeout=REQUEST_TIMEOUT) as smtp:
            smtp.noop()
        latency_ms = round((time.monotonic() - started) * 1000)
        return {"name": "Mail Server (SMTP)", "status": "online", "latency_ms": latency_ms}
    except Exception as exc:  # noqa: BLE001 - external service, keep the app alive
        current_app.logger.warning("Mail server health check failed: %s", exc)
        return {"name": "Mail Server (SMTP)", "status": "offline", "error": str(exc)}


@stats_bp.route("/services")
@require_role(["owner"])
def services_health():
    """Live status of the external services the app depends on.

    Each check makes a real, lightweight network call -- nothing here is
    hardcoded to "Online". Services without an API key configured are
    reported as 'not_configured' rather than faked as healthy.
    """
    services = [
        _check_clerk(),
        _check_virustotal(),
        _check_safe_browsing(),
        _check_mail_server(),
    ]
    return jsonify({"success": True, "services": services, "checked_at": _iso(datetime.utcnow())})
