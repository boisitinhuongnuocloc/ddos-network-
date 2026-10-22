import json
import time
import urllib.error
import urllib.request

import os

REPORT_BASE_URL = "http://127.0.0.1:8080"


def _load_token():
    env_token = os.environ.get("API_AUTH_TOKEN")
    if env_token:
        return env_token
    # Fallback: token do app_server sinh ra và lưu trong monitoring/.api_token
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".api_token")
        with open(path, "r", encoding="utf-8") as f:
            token = f.read().strip()
            if token:
                return token
    except Exception:
        pass
    return "nexus_internal_token"


API_AUTH_TOKEN = _load_token()


def _post(path, payload, timeout=2.0, retries=1):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(
                REPORT_BASE_URL + path,
                data=body,
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "X-API-Token": API_AUTH_TOKEN
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return 200 <= response.status < 300
        except (OSError, urllib.error.URLError, ValueError):
            if attempt < retries:
                time.sleep(0.3)
    return False


def report_module(name, status, target=None, message=None, metrics=None, started_at=None):
    payload = {
        "name": str(name),
        "status": str(status).upper(),
        "target": str(target or "None"),
        "message": str(message or ""),
        "metrics": metrics if isinstance(metrics, dict) else {},
    }
    if isinstance(started_at, (int, float)):
        payload["started_at"] = started_at
    return _post("/api/module-status", payload)


def report_event(message, event_type="info", module=None, target=None):
    return _post(
        "/api/events",
        {
            "message": str(message),
            "type": str(event_type),
            "module": str(module) if module else None,
            "target": str(target) if target else None,
            "timestamp": time.time(),
        },
    )


def report_finding(module, title, target=None, severity="info", details=None):
    return _post(
        "/api/findings",
        {
            "module": str(module),
            "title": str(title),
            "target": str(target or "None"),
            "severity": str(severity),
            "details": str(details or ""),
            "timestamp": time.time(),
        },
    )
