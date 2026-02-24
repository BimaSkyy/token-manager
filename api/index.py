"""
YouTube Token Manager — Vercel Deployment
Menyimpan OAuth token di Vercel KV (Redis), bukan GitHub.
Aman, enkripsi at-rest, tidak bisa diakses publik.
"""

import os
import json
import time
import secrets
from datetime import datetime, timezone

from flask import Flask, request, jsonify, redirect, render_template_string

# ── Google OAuth ──────────────────────────────────────────────
try:
    from google_auth_oauthlib.flow import Flow
    from google.auth.transport.requests import Request as GRequest
    from google.oauth2.credentials import Credentials
    GOOGLE_OK = True
except ImportError:
    GOOGLE_OK = False

# ── Vercel KV (Redis) ─────────────────────────────────────────
try:
    import upstash_redis
    from upstash_redis import Redis
    _redis = Redis(
        url=os.environ.get("KV_REST_API_URL", ""),
        token=os.environ.get("KV_REST_API_TOKEN", "")
    )
    KV_OK = True
except Exception:
    _redis = None
    KV_OK = False

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────
SCOPES = [
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/youtube.upload",
]

# Ambil dari environment variable Vercel
ADMIN_KEY      = os.environ.get("ADMIN_KEY", "")       # Password untuk akses UI
API_SECRET_KEY = os.environ.get("API_SECRET_KEY", "")  # Secret untuk Koyeb ambil token
CLIENT_ID      = os.environ.get("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET  = os.environ.get("GOOGLE_CLIENT_SECRET", "")
VERCEL_URL     = os.environ.get("VERCEL_URL", "localhost:5000")

TOKEN_KV_KEY   = "youtube_oauth_token"
STATE_KV_KEY   = "oauth_state"

# ─────────────────────────────────────────────────────────────
# KV Helpers
# ─────────────────────────────────────────────────────────────

def kv_get(key: str):
    if not KV_OK or not _redis: return None
    try:
        val = _redis.get(key)
        if val is None: return None
        return json.loads(val) if isinstance(val, str) else val
    except Exception as e:
        print(f"[KV] GET error {key}: {e}")
        return None

def kv_set(key: str, value, ttl_seconds: int = None):
    if not KV_OK or not _redis: return False
    try:
        data = json.dumps(value)
        if ttl_seconds:
            _redis.setex(key, ttl_seconds, data)
        else:
            _redis.set(key, data)
        return True
    except Exception as e:
        print(f"[KV] SET error {key}: {e}")
        return False

def kv_delete(key: str):
    if not KV_OK or not _redis: return False
    try:
        _redis.delete(key)
        return True
    except Exception as e:
        print(f"[KV] DELETE error {key}: {e}")
        return False

# ─────────────────────────────────────────────────────────────
# Token Helpers
# ─────────────────────────────────────────────────────────────

def load_token() -> dict | None:
    """Ambil token dari KV."""
    return kv_get(TOKEN_KV_KEY)

def save_token(token_dict: dict) -> bool:
    """Simpan token ke KV (tanpa expiry — token dikelola manual)."""
    token_dict["saved_at"] = datetime.now(timezone.utc).isoformat()
    return kv_set(TOKEN_KV_KEY, token_dict)

def get_valid_credentials():
    """
    Ambil credentials yang valid. Auto-refresh jika expired.
    Return: (Credentials, error_string)
    """
    if not GOOGLE_OK:
        return None, "Library google-auth tidak tersedia"

    token_data = load_token()
    if not token_data:
        return None, "Token belum ada. Lakukan login OAuth dulu."

    try:
        creds = Credentials.from_authorized_user_info(token_data, SCOPES)
    except Exception as e:
        return None, f"Token tidak valid: {e}"

    if creds.valid:
        return creds, None

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(GRequest())
            # Simpan token baru hasil refresh ke KV
            new_data = json.loads(creds.to_json())
            new_data["refreshed_at"] = datetime.now(timezone.utc).isoformat()
            save_token(new_data)
            print("[AUTH] Token auto-refresh berhasil, disimpan ke KV")
            return creds, None
        except Exception as e:
            return None, f"Refresh token gagal: {e}. Silakan login OAuth ulang."

    return None, "Token expired dan tidak ada refresh_token. Login OAuth ulang."

def token_status() -> dict:
    """Buat ringkasan status token untuk UI."""
    token_data = load_token()
    if not token_data:
        return {
            "exists": False,
            "valid": False,
            "status": "Belum ada token",
            "color": "red",
        }

    creds, err = get_valid_credentials()
    if creds and creds.valid:
        expiry = token_data.get("expiry", "")
        saved_at = token_data.get("saved_at", "")
        refreshed_at = token_data.get("refreshed_at", "")
        has_refresh_token = bool(token_data.get("refresh_token"))
        return {
            "exists": True,
            "valid": True,
            "status": "✅ Token valid & aktif",
            "color": "green",
            "expiry": expiry,
            "saved_at": saved_at,
            "refreshed_at": refreshed_at,
            "has_refresh_token": has_refresh_token,
            "auto_refresh": has_refresh_token,
        }
    else:
        return {
            "exists": True,
            "valid": False,
            "status": f"❌ {err}",
            "color": "red",
            "has_refresh_token": bool(token_data.get("refresh_token")),
        }

# ─────────────────────────────────────────────────────────────
# Auth Helpers
# ─────────────────────────────────────────────────────────────

def check_admin(req) -> bool:
    """Cek admin key dari header atau query param."""
    key = (
        req.headers.get("X-Admin-Key") or
        req.args.get("admin_key") or
        req.json.get("admin_key") if req.is_json else None
    )
    return key == ADMIN_KEY if ADMIN_KEY else True

def check_api_secret(req) -> bool:
    """Cek API secret untuk Koyeb."""
    key = (
        req.headers.get("X-API-Secret") or
        req.args.get("api_secret")
    )
    return key == API_SECRET_KEY if API_SECRET_KEY else False

def get_redirect_uri():
    base = VERCEL_URL
    if not base.startswith("http"):
        base = f"https://{base}"
    return f"{base}/api/callback"

# ─────────────────────────────────────────────────────────────
# UI Template
# ─────────────────────────────────────────────────────────────

UI_HTML = """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>YouTube Token Manager</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f0f0f; color: #e0e0e0; min-height: 100vh; }
  .container { max-width: 680px; margin: 0 auto; padding: 40px 20px; }

  h1 { font-size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 4px; }
  .subtitle { color: #888; font-size: 0.85rem; margin-bottom: 32px; }

  .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
  .card h2 { font-size: 1rem; font-weight: 600; color: #fff; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }

  .status-badge { display: inline-flex; align-items: center; gap: 8px; padding: 10px 16px; border-radius: 8px; font-size: 0.9rem; font-weight: 500; margin-bottom: 16px; width: 100%; }
  .status-badge.green { background: #0d2b1a; color: #4ade80; border: 1px solid #166534; }
  .status-badge.red { background: #2b0d0d; color: #f87171; border: 1px solid #7f1d1d; }
  .status-badge.yellow { background: #2b240d; color: #fbbf24; border: 1px solid #7f5f1d; }

  .meta { font-size: 0.78rem; color: #666; line-height: 1.8; }
  .meta span { color: #999; }

  .btn { display: inline-flex; align-items: center; gap: 8px; padding: 10px 20px; border-radius: 8px; font-size: 0.88rem; font-weight: 600; text-decoration: none; border: none; cursor: pointer; transition: all 0.15s; }
  .btn-primary { background: #ff0000; color: #fff; }
  .btn-primary:hover { background: #cc0000; }
  .btn-secondary { background: #2a2a2a; color: #ccc; border: 1px solid #3a3a3a; }
  .btn-secondary:hover { background: #333; color: #fff; }
  .btn-warning { background: #7f3d00; color: #fbbf24; border: 1px solid #a35200; }
  .btn-warning:hover { background: #a35200; }
  .btn-danger { background: #7f1d1d; color: #f87171; border: 1px solid #991b1b; }
  .btn-danger:hover { background: #991b1b; }

  .btn-group { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }

  .code-box { background: #111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 14px; font-family: 'Courier New', monospace; font-size: 0.78rem; color: #7dd3fc; word-break: break-all; line-height: 1.6; }
  .code-box .comment { color: #555; }

  .divider { border: none; border-top: 1px solid #2a2a2a; margin: 20px 0; }

  .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 600; background: #1e3a5f; color: #7dd3fc; margin-right: 4px; }

  .alert { padding: 12px 16px; border-radius: 8px; font-size: 0.85rem; margin-bottom: 16px; }
  .alert-info { background: #0c1f35; color: #7dd3fc; border: 1px solid #1e3a5f; }
  .alert-warn { background: #2b1a00; color: #fbbf24; border: 1px solid #7f5f1d; }

  form { display: flex; flex-direction: column; gap: 12px; }
  label { font-size: 0.82rem; color: #999; margin-bottom: 2px; display: block; }
  input[type="password"], input[type="text"] {
    width: 100%; padding: 10px 14px; background: #111; border: 1px solid #2a2a2a;
    border-radius: 8px; color: #e0e0e0; font-size: 0.88rem;
  }
  input:focus { outline: none; border-color: #ff0000; }
</style>
</head>
<body>
<div class="container">
  <h1>🔑 YouTube Token Manager</h1>
  <p class="subtitle">Kelola OAuth token YouTube untuk upload otomatis</p>

  <!-- Status Token -->
  <div class="card">
    <h2>📊 Status Token</h2>
    <div class="status-badge {{ status.color }}">
      {{ status.status }}
    </div>
    {% if status.exists %}
    <div class="meta">
      {% if status.saved_at %}<div>Disimpan: <span>{{ status.saved_at }}</span></div>{% endif %}
      {% if status.refreshed_at %}<div>Terakhir refresh: <span>{{ status.refreshed_at }}</span></div>{% endif %}
      {% if status.expiry %}<div>Expiry access token: <span>{{ status.expiry }}</span></div>{% endif %}
      <div>Auto-refresh: <span>{{ '✅ Aktif (ada refresh_token)' if status.auto_refresh else '❌ Tidak aktif' }}</span></div>
    </div>
    {% endif %}

    <div class="btn-group">
      <a href="/api/login?admin_key={{ admin_key }}" class="btn btn-primary">
        🔐 Login OAuth YouTube
      </a>
      {% if status.valid %}
      <a href="/api/refresh?admin_key={{ admin_key }}" class="btn btn-secondary">
        🔄 Force Refresh Token
      </a>
      {% endif %}
      {% if status.exists %}
      <a href="/api/revoke?admin_key={{ admin_key }}" class="btn btn-danger"
         onclick="return confirm('Yakin hapus token?')">
        🗑 Hapus Token
      </a>
      {% endif %}
    </div>
  </div>

  <!-- API Endpoint untuk Koyeb -->
  <div class="card">
    <h2>🔌 API Endpoint untuk Koyeb</h2>
    <div class="alert alert-info">
      Koyeb akan menggunakan endpoint ini untuk mengambil token yang selalu fresh.
      Token otomatis di-refresh setiap kali endpoint ini dipanggil jika expired.
    </div>
    <div class="code-box">
      <div class="comment"># Tambahkan ke environment variable Koyeb:</div><br>
      TOKEN_MANAGER_URL = https://{{ vercel_url }}<br>
      TOKEN_MANAGER_SECRET = (isi API_SECRET_KEY kamu)<br><br>
      <div class="comment"># Cara ambil token dari Koyeb:</div><br>
      GET {{ vercel_url }}/api/token<br>
      Header: X-API-Secret: YOUR_SECRET
    </div>
    <div class="btn-group">
      <a href="/api/token-info?admin_key={{ admin_key }}" class="btn btn-secondary" target="_blank">
        👁 Lihat Token Info (Admin)
      </a>
    </div>
  </div>

  <!-- Setup Guide -->
  <div class="card">
    <h2>📋 Cara Setup</h2>
    <div class="alert alert-warn">
      Pastikan environment variables Vercel sudah di-set sebelum login OAuth.
    </div>
    <div class="code-box">
      <div class="comment"># Environment Variables yang wajib di Vercel:</div><br>
      GOOGLE_CLIENT_ID      = (dari Google Cloud Console)<br>
      GOOGLE_CLIENT_SECRET  = (dari Google Cloud Console)<br>
      ADMIN_KEY             = (password bebas untuk akses UI)<br>
      API_SECRET_KEY        = (password bebas untuk Koyeb)<br>
      KV_REST_API_URL       = (dari Vercel KV dashboard)<br>
      KV_REST_API_TOKEN     = (dari Vercel KV dashboard)<br><br>
      <div class="comment"># Di Google Cloud Console:</div><br>
      Authorized redirect URI:<br>
      https://{{ vercel_url }}/api/callback
    </div>
  </div>
</div>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────
# Routes — UI
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    admin_key = request.args.get("admin_key", "")
    if ADMIN_KEY and admin_key != ADMIN_KEY:
        return """
        <html><body style="background:#0f0f0f;color:#e0e0e0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;">
        <div style="text-align:center">
          <div style="font-size:3rem;margin-bottom:16px">🔒</div>
          <div style="font-size:1.1rem;margin-bottom:20px">Masukkan Admin Key</div>
          <form method="GET">
            <input type="password" name="admin_key" placeholder="Admin Key..."
              style="padding:10px 14px;background:#1a1a1a;border:1px solid #333;border-radius:8px;color:#fff;font-size:0.9rem;margin-right:8px">
            <button type="submit" style="padding:10px 20px;background:#ff0000;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600">
              Masuk
            </button>
          </form>
        </div></body></html>
        """

    status = token_status()
    vercel_url = VERCEL_URL
    if not vercel_url.startswith("http"):
        vercel_url = f"https://{vercel_url}"

    return render_template_string(UI_HTML,
        status=status,
        admin_key=admin_key,
        vercel_url=vercel_url
    )

# ─────────────────────────────────────────────────────────────
# Routes — OAuth Flow
# ─────────────────────────────────────────────────────────────

@app.route("/api/login")
def oauth_login():
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401
    if not CLIENT_ID or not CLIENT_SECRET:
        return jsonify({"error": "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET belum di-set di environment Vercel"}), 500
    if not GOOGLE_OK:
        return jsonify({"error": "Library google-auth-oauthlib tidak tersedia"}), 500

    client_config = {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [get_redirect_uri()],
        }
    }

    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = get_redirect_uri()

    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",  # Wajib agar dapat refresh_token
        include_granted_scopes="true"
    )

    # Simpan state ke KV (TTL 10 menit)
    kv_set(STATE_KV_KEY, {"state": state, "admin_key": request.args.get("admin_key", "")}, ttl_seconds=600)

    return redirect(auth_url)


@app.route("/api/callback")
def oauth_callback():
    if not GOOGLE_OK:
        return "Library google-auth tidak tersedia", 500

    # Ambil state dari KV
    saved = kv_get(STATE_KV_KEY)
    if not saved:
        return "OAuth state expired atau tidak valid. Coba login lagi.", 400

    admin_key = saved.get("admin_key", "")
    kv_delete(STATE_KV_KEY)

    code = request.args.get("code")
    if not code:
        return "Tidak ada authorization code dari Google.", 400

    client_config = {
        "web": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [get_redirect_uri()],
        }
    }

    try:
        flow = Flow.from_client_config(client_config, scopes=SCOPES)
        flow.redirect_uri = get_redirect_uri()
        flow.fetch_token(code=code)
        creds = flow.credentials

        token_dict = json.loads(creds.to_json())
        token_dict["obtained_at"] = datetime.now(timezone.utc).isoformat()
        save_token(token_dict)

        has_refresh = bool(token_dict.get("refresh_token"))
        return redirect(f"/?admin_key={admin_key}&login=success")
    except Exception as e:
        return f"Gagal mengambil token: {e}", 500


@app.route("/api/refresh")
def manual_refresh():
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    creds, err = get_valid_credentials()
    if err:
        return jsonify({"success": False, "error": err}), 400

    return jsonify({
        "success": True,
        "message": "Token berhasil di-refresh dan disimpan ke KV",
        "valid": creds.valid,
        "expiry": str(creds.expiry) if creds.expiry else None
    })


@app.route("/api/revoke")
def revoke_token():
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    kv_delete(TOKEN_KV_KEY)
    admin_key = request.args.get("admin_key", "")
    return redirect(f"/?admin_key={admin_key}")

# ─────────────────────────────────────────────────────────────
# Routes — API untuk Koyeb
# ─────────────────────────────────────────────────────────────

@app.route("/api/token")
def get_token_for_koyeb():
    """
    Endpoint utama yang dipanggil Koyeb untuk ambil token.
    Auto-refresh jika expired. Return token JSON yang siap dipakai.
    """
    if not check_api_secret(request):
        return jsonify({"success": False, "error": "Unauthorized. Set X-API-Secret header."}), 401

    creds, err = get_valid_credentials()
    if err:
        return jsonify({
            "success": False,
            "error": err,
            "action_required": "Login OAuth di web token manager"
        }), 401

    token_data = load_token()
    return jsonify({
        "success": True,
        "token": token_data,  # Full token JSON untuk Credentials.from_authorized_user_info()
        "valid": creds.valid,
        "expiry": str(creds.expiry) if creds.expiry else None,
        "auto_refreshed": True,
        "fetched_at": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/token-info")
def token_info_admin():
    """Info token untuk admin (tanpa expose full secret)."""
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    status = token_status()
    token_data = load_token()
    safe_info = {}
    if token_data:
        safe_info = {
            "has_access_token": bool(token_data.get("token")),
            "has_refresh_token": bool(token_data.get("refresh_token")),
            "scopes": token_data.get("scopes", []),
            "expiry": token_data.get("expiry"),
            "saved_at": token_data.get("saved_at"),
            "refreshed_at": token_data.get("refreshed_at"),
            "obtained_at": token_data.get("obtained_at"),
        }
    return jsonify({"status": status, "token_info": safe_info})


@app.route("/api/health")
def health():
    return jsonify({
        "ok": True,
        "kv_connected": KV_OK,
        "google_lib": GOOGLE_OK,
        "token_exists": load_token() is not None,
        "time": datetime.now(timezone.utc).isoformat()
    })


if __name__ == "__main__":
    app.run(debug=True, port=5001)
