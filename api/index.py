"""
YouTube Token Store — Vercel
Fungsi: hanya simpan & ambil token. Semua logic ada di Koyeb.
"""

import os
import json
import subprocess
import sys
from datetime import datetime, timezone
from flask import Flask, request, jsonify

# Auto-install redis jika belum ada
try:
    import redis
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "redis==5.0.1"], check=True)
    import redis

app = Flask(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "")
SECRET    = os.environ.get("STORE_SECRET", "")
TOKEN_KEY = "yt_token"

# ─────────────────────────────────────────────────────────────
# Redis Helpers
# ─────────────────────────────────────────────────────────────

def get_redis():
    if not REDIS_URL: return None
    try:
        return redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=10)
    except Exception as e:
        print(f"[REDIS] Connect error: {e}")
        return None

def kv_set(key: str, value: str) -> bool:
    r = get_redis()
    if not r: return False
    try:
        r.set(key, value)
        return True
    except Exception as e:
        print(f"[REDIS SET] error: {e}")
        return False

def kv_get(key: str):
    r = get_redis()
    if not r: return None
    try:
        return r.get(key)
    except Exception as e:
        print(f"[REDIS GET] error: {e}")
        return None

# ─────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────

def auth_ok() -> bool:
    provided = (
        request.headers.get("X-Store-Secret") or
        request.args.get("secret")
    )
    return provided == SECRET if SECRET else False

# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/api/save-token", methods=["POST"])
def save_token():
    if not auth_ok():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data  = request.get_json(silent=True) or {}
    token = data.get("token")
    if not token:
        return jsonify({"ok": False, "error": "Field 'token' tidak ada"}), 400

    payload = {
        "token": token,
        "saved_at": datetime.now(timezone.utc).isoformat()
    }

    ok = kv_set(TOKEN_KEY, json.dumps(payload))
    if ok:
        return jsonify({"ok": True, "saved_at": payload["saved_at"]})
    else:
        return jsonify({"ok": False, "error": "Gagal simpan ke Redis"}), 500


@app.route("/api/get-token", methods=["GET"])
def get_token():
    if not auth_ok():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    raw = kv_get(TOKEN_KEY)
    if not raw:
        return jsonify({"ok": False, "error": "Token belum ada. Login OAuth dulu di Koyeb."}), 404

    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
        return jsonify({
            "ok": True,
            "token": payload.get("token"),
            "saved_at": payload.get("saved_at")
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"Token corrupt: {e}"}), 500


@app.route("/api/status", methods=["GET"])
def status():
    raw = kv_get(TOKEN_KEY)
    if not raw:
        return jsonify({"token_exists": False, "saved_at": None})
    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
        return jsonify({"token_exists": True, "saved_at": payload.get("saved_at")})
    except Exception:
        return jsonify({"token_exists": False, "saved_at": None})


@app.route("/api/health", methods=["GET"])
def health():
    redis_ok = False
    error_msg = None
    try:
        r = get_redis()
        if r:
            r.ping()
            redis_ok = True
    except Exception as e:
        error_msg = str(e)
    return jsonify({
        "ok": True,
        "redis_connected": redis_ok,
        "redis_url_set": bool(REDIS_URL),
        "secret_configured": bool(SECRET),
        "error": error_msg,
        "time": datetime.now(timezone.utc).isoformat()
    })


@app.route("/")
def index():
    raw = kv_get(TOKEN_KEY)
    token_exists = False
    saved_at = "-"
    if raw:
        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
            token_exists = True
            saved_at = payload.get("saved_at", "-")
        except Exception:
            pass

    status_color = "#4ade80" if token_exists else "#f87171"
    status_text  = "✅ Token tersimpan" if token_exists else "❌ Belum ada token"

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YT Token Store</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f0f0f; color: #e0e0e0;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
  .card {{ background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 16px;
           padding: 40px; max-width: 420px; width: 90%; text-align: center; }}
  h1 {{ font-size: 1.3rem; margin-bottom: 4px; }}
  .sub {{ color: #666; font-size: 0.82rem; margin-bottom: 28px; }}
  .badge {{ display: inline-block; padding: 10px 20px; border-radius: 8px;
            font-weight: 600; font-size: 0.9rem; color: {status_color};
            background: {status_color}18; border: 1px solid {status_color}44;
            margin-bottom: 16px; }}
  .meta {{ font-size: 0.78rem; color: #555; margin-bottom: 24px; }}
  .endpoints {{ background: #111; border: 1px solid #222; border-radius: 8px;
                padding: 14px; font-family: monospace; font-size: 0.75rem;
                color: #7dd3fc; text-align: left; line-height: 2; }}
  .dim {{ color: #444; }}
</style>
</head>
<body>
<div class="card">
  <h1>🔐 YT Token Store</h1>
  <p class="sub">Token disimpan di Redis — dikelola oleh Koyeb</p>
  <div class="badge">{status_text}</div>
  <div class="meta">Terakhir disimpan: {saved_at}</div>
  <div class="endpoints">
    <span class="dim">POST</span> /api/save-token<br>
    <span class="dim">GET&nbsp;</span> /api/get-token<br>
    <span class="dim">GET&nbsp;</span> /api/status<br>
    <span class="dim">GET&nbsp;</span> /api/health
  </div>
</div>
</body>
</html>"""


if __name__ == "__main__":
    app.run(debug=True, port=5001)
