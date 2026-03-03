import os
import time
import sqlite3
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect, jsonify, make_response
from itsdangerous import URLSafeSerializer, BadSignature

# =========================
# ENV VARS REQUIRED (Render)
# =========================
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")  # e.g. https://steam-link.onrender.com
STEAM_API_KEY = os.getenv("STEAM_API_KEY", "")   # optional, used for Steam persona name
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")  # optional, used to auto-add role
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "")    # optional
LINKED_ROLE_ID = os.getenv("LINKED_ROLE_ID", "")        # optional
APP_SECRET = os.getenv("APP_SECRET", "")                # REQUIRED for secure state

# Render port
PORT = int(os.getenv("PORT", "10000"))

if not APP_SECRET:
    # Don't crash hard on import; show a useful message on the / endpoint.
    print("WARNING: Missing env var APP_SECRET")

app = Flask(__name__)

# =========================
# DB (SQLite)
# =========================
DB_PATH = os.getenv("DB_PATH", "steam_links.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS links (
        discord_user_id TEXT PRIMARY KEY,
        steam_id TEXT,
        linked_at INTEGER,
        last_role_attempt INTEGER DEFAULT 0,
        last_role_status INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

init_db()

# =========================
# STATE SIGNING
# =========================
def serializer():
    # URLSafe serializer so the state can be passed in query strings safely
    return URLSafeSerializer(APP_SECRET, salt="steam-link-state")

def make_state(discord_user_id: str) -> str:
    s = serializer()
    payload = {
        "d": str(discord_user_id),
        "t": int(time.time())
    }
    return s.dumps(payload)

def read_state(state: str) -> str:
    s = serializer()
    payload = s.loads(state)  # may raise BadSignature
    return payload["d"]

# =========================
# STEAM OPENID CONSTANTS
# =========================
STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"

OPENID_NS = "http://specs.openid.net/auth/2.0"
IDENTIFIER_SELECT = "http://specs.openid.net/auth/2.0/identifier_select"

def steam_auth_url(return_to: str, realm: str, state: str) -> str:
    params = {
        "openid.ns": OPENID_NS,
        "openid.mode": "checkid_setup",
        "openid.return_to": f"{return_to}?state={state}",
        "openid.realm": realm,
        "openid.identity": IDENTIFIER_SELECT,
        "openid.claimed_id": IDENTIFIER_SELECT,
    }
    return f"{STEAM_OPENID_URL}?{urlencode(params)}"

def verify_steam_openid(args) -> str | None:
    """
    Verify Steam OpenID response with check_authentication.
    Returns steam_id (str) if valid, else None.
    """
    # Build data from Steam response
    data = dict(args)
    data["openid.mode"] = "check_authentication"

    r = requests.post(STEAM_OPENID_URL, data=data, timeout=15)
    if r.status_code != 200:
        return None

    if "is_valid:true" not in r.text:
        return None

    claimed_id = args.get("openid.claimed_id", "")
    # claimed_id looks like: https://steamcommunity.com/openid/id/7656119...
    if "/openid/id/" not in claimed_id:
        return None

    steam_id = claimed_id.split("/openid/id/")[-1].strip("/")
    if not steam_id.isdigit():
        return None

    return steam_id

def get_steam_persona(steam_id: str) -> str | None:
    if not STEAM_API_KEY:
        return None
    url = (
        "http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/"
        f"?key={STEAM_API_KEY}&steamids={steam_id}"
    )
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        players = data.get("response", {}).get("players", [])
        if not players:
            return None
        return players[0].get("personaname")
    except Exception:
        return None

# =========================
# DISCORD ROLE (OPTIONAL)
# =========================
def discord_add_role(discord_user_id: str) -> tuple[bool, str]:
    """
    Adds LINKED_ROLE_ID to user in DISCORD_GUILD_ID.
    Returns (ok, message).
    Handles 429 gracefully.
    """
    if not (DISCORD_BOT_TOKEN and DISCORD_GUILD_ID and LINKED_ROLE_ID):
        return (False, "Discord role not configured (missing env vars).")

    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}

    r = requests.put(url, headers=headers, timeout=15)

    if r.status_code in (204, 201):
        return (True, "Role added.")
    if r.status_code == 429:
        try:
            j = r.json()
            retry_after = j.get("retry_after", 5)
        except Exception:
            retry_after = 5
        return (False, f"Rate limited by Discord (429). Retry after ~{retry_after}s.")
    return (False, f"Discord role add failed: {r.status_code} {r.text[:200]}")

def should_attempt_role(discord_user_id: str, cooldown_seconds: int = 600) -> bool:
    """
    Avoid spamming Discord API (global rate limits).
    Only try once every cooldown_seconds per user.
    """
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT last_role_attempt FROM links WHERE discord_user_id = ?", (discord_user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return True
    last_attempt = int(row["last_role_attempt"] or 0)
    return (int(time.time()) - last_attempt) > cooldown_seconds

def update_role_attempt(discord_user_id: str, status_code: int):
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE links
        SET last_role_attempt = ?, last_role_status = ?
        WHERE discord_user_id = ?
    """, (int(time.time()), int(status_code), str(discord_user_id)))
    conn.commit()
    conn.close()

# =========================
# ROUTES
# =========================

@app.get("/")
def home():
    # Useful landing page + shows exactly how to use the service
    missing = []
    if not BASE_URL:
        missing.append("BASE_URL")
    if not APP_SECRET:
        missing.append("APP_SECRET")

    if missing:
        return make_response(
            "steam-link service is running ✅\n"
            f"Missing env vars: {', '.join(missing)}\n"
            "Fix your Render Environment Variables then redeploy.\n",
            200,
        )

    return (
        "steam-link service is running ✅\n\n"
        "Use:\n"
        f"{BASE_URL}/steam/start?discord_user_id=YOUR_DISCORD_ID\n\n"
        "Bot uses:\n"
        f"{BASE_URL}/link/status?discord_user_id=YOUR_DISCORD_ID\n"
    ), 200

@app.get("/steam/start")
def steam_start():
    if not BASE_URL:
        return "Missing env var BASE_URL", 500
    if not APP_SECRET:
        return "Missing env var APP_SECRET", 500

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return "Invalid or missing discord_user_id", 400

    state = make_state(discord_user_id)
    return_to = f"{BASE_URL}/steam/callback"
    realm = BASE_URL

    return redirect(steam_auth_url(return_to=return_to, realm=realm, state=state))

@app.get("/steam/callback")
def steam_callback():
    # 1) Validate state
    if not APP_SECRET:
        return "Missing env var APP_SECRET", 500

    state = request.args.get("state", "")
    if not state:
        return "Missing state", 400

    try:
        discord_user_id = read_state(state)
    except BadSignature:
        return "Invalid state (signature mismatch)", 400
    except Exception as e:
        return f"Invalid state: {e}", 400

    # 2) Verify OpenID response with Steam
    steam_id = verify_steam_openid(request.args)
    if not steam_id:
        return "Steam verification failed", 400

    # 3) Store link
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO links (discord_user_id, steam_id, linked_at, last_role_attempt, last_role_status)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(discord_user_id) DO UPDATE SET
            steam_id = excluded.steam_id,
            linked_at = excluded.linked_at
    """, (str(discord_user_id), str(steam_id), int(time.time()), 0, 0))
    conn.commit()
    conn.close()

    # 4) Attempt to add role (optional) without crashing on 429
    role_msg = ""
    if should_attempt_role(discord_user_id):
        ok, msg = discord_add_role(discord_user_id)
        role_msg = f" BUT role add: {msg}"
        # Track attempt; if ok mark 204, if not 429/other
        status = 204 if ok else (429 if "429" in msg else 400)
        update_role_attempt(discord_user_id, status)
    else:
        role_msg = " (Role add skipped for now: cooldown active to avoid rate limits.)"

    return f"Linked ✅ SteamID: {steam_id}{role_msg}", 200

@app.get("/link/status")
def link_status():
    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return jsonify({"linked": False, "error": "invalid_discord_user_id"}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT steam_id, linked_at FROM links WHERE discord_user_id = ?", (discord_user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"linked": False}), 200

    steam_id = row["steam_id"]
    persona = get_steam_persona(steam_id) if steam_id else None

    return jsonify({
        "linked": True,
        "discord_user_id": discord_user_id,
        "steam_id": steam_id,
        "mx_name": persona,  # usually Steam display name
        "linked_at": row["linked_at"]
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
