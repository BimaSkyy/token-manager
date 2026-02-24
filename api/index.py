"""
YouTube Token Store — Vercel
Pakai JSONBin.io untuk simpan token. Gratis, no library, cukup requests.
"""

import os
import json
import requests
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

# JSONBin.io config — set di env var Vercel
JSONBIN_BIN_ID  = os.environ.get("JSONBIN_BIN_ID", "")   # ID bin dari JSONBin
JSONBIN_API_KEY = os.environ.get("JSONBIN_API_KEY", "")   # Master key dari JSONBin
SECRET          = os.environ.get("STORE_SECRET", "")

JSONBIN_URL = f"https://api.jsonbin.io/v3/b/{JSONBIN_BIN_ID}"

# ─────────────────────────────────────────────────────────────
# JSONBin Helpers
# ─────────────────────────────────────────────────────────────

def jb_headers():
    return {
        "X-Master-Key": JSONBIN_API_KEY,
        "Content-Type": "application/json"
    }

def jb_get():
    """Ambil data dari JSONBin."""
    if not JSONBIN_BIN_ID or not JSONBIN_API_KEY:
        return None
    try:
        r = requests.get(JSONBIN_URL + "/latest", headers=jb_headers(), timeout=10)
        if r.status_code == 200:
            return r.json().get("record", {})
        return None
    except Exception as e:
        print(f"[JSONBIN] GET error: {e}")
        return None

def jb_put(data: dict):
    """Update data di JSONBin."""
    if not JSONBIN_BIN_ID or not JSONBIN_API_KEY:
        return False
    try:
        r = requests.put(JSONBIN_URL, headers=jb_headers(), json=data, timeout=10)
        return r.status_code == 200
    except Exception as e:
        print(f"[JSONBIN] PUT error: {e}")
        return False

# ─────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────

def auth_ok():
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

    ok = jb_put(payload)
    if ok:
        return jsonify({"ok": True, "saved_at": payload["saved_at"]})
    else:
        return jsonify({"ok": False, "error": "Gagal simpan ke JSONBin"}), 500


@app.route("/api/get-token", methods=["GET"])
def get_token():
    if not auth_ok():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = jb_get()
    if not data or not data.get("token"):
        return jsonify({"ok": False, "error": "Token belum ada. Login OAuth dulu di Koyeb."}), 404

    return jsonify({
        "ok": True,
        "token": data.get("token"),
        "saved_at": data.get("saved_at")
    })


@app.route("/api/status", methods=["GET"])
def status():
    data = jb_get()
    if not data or not data.get("token"):
        return jsonify({"token_exists": False, "saved_at": None})
    return jsonify({"token_exists": True, "saved_at": data.get("saved_at")})


@app.route("/api/health", methods=["GET"])
def health():
    bin_ok = bool(JSONBIN_BIN_ID and JSONBIN_API_KEY)
    return jsonify({
        "ok": True,
        "storage": "jsonbin.io",
        "jsonbin_configured": bin_ok,
        "secret_configured": bool(SECRET),
        "time": datetime.now(timezone.utc).isoformat()
    })


@app.route("/")
def index():
    data = jb_get()
    token_exists = bool(data and data.get("token"))
    saved_at = data.get("saved_at", "-") if data else "-"

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
  <p class="sub">Token disimpan di JSONBin.io — dikelola oleh Koyeb</p>
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
