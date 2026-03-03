# app.py
import os
import time
import sqlite3
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect, jsonify

from itsdangerous import URLSafeSerializer, BadSignature

# ----------------------------
# Config / Env
# ----------------------------
REQUIRED_ENV = [
    "BASE_URL",            # e.g. https://steam-link.onrender.com
    "APP_SECRET",          # random long string
    "DISCORD_BOT_TOKEN",   # your bot token
    "DISCORD_GUILD_ID",    # your server id
    "LINKED_ROLE_ID",      # role id to give after linking
]

BASE_URL = os.getenv("BASE_URL", "").rstrip("/")
APP_SECRET = os.getenv("APP_SECRET", "")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "")
LINKED_ROLE_ID = os.getenv("LINKED_ROLE_ID", "")
STEAM_API_KEY = os.getenv("STEAM_API_KEY", "")  # optional for later features

app = Flask(__name__)

def missing_env():
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    return missing

serializer = URLSafeSerializer(APP_SECRET or "dev-secret", salt="steam-link-state")

# ----------------------------
# Database
# ----------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "steam_links.db")

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def db_init():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS links (
            discord_user_id TEXT PRIMARY KEY,
            steam_id TEXT NOT NULL,
            linked_at INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Flask 3 compatible: init on startup
db_init()

# ----------------------------
# Helpers
# ----------------------------
STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login"

def build_state(discord_user_id: str) -> str:
    # Put 2 values in state to avoid your "expected 2, got 1" bug
    nonce = secrets.token_urlsafe(16)
    now = int(time.time())

    # store nonce (optional but helps prevent replay)
    conn = db_conn()
    conn.execute("INSERT OR REPLACE INTO nonces (nonce, created_at) VALUES (?, ?)", (nonce, now))
    conn.commit()
    conn.close()

    payload = {"d": str(discord_user_id), "n": nonce, "t": now}
    return serializer.dumps(payload)

def parse_state(state: str):
    payload = serializer.loads(state)
    # Validate shape
    if not isinstance(payload, dict):
        raise ValueError("state payload invalid")
    if "d" not in payload or "n" not in payload:
        raise ValueError("state payload missing fields")
    return payload

def verify_nonce(nonce: str, max_age_seconds: int = 15 * 60) -> bool:
    now = int(time.time())
    conn = db_conn()
    row = conn.execute("SELECT nonce, created_at FROM nonces WHERE nonce = ?", (nonce,)).fetchone()
    conn.close()
    if not row:
        return False
    created_at = int(row["created_at"])
    return (now - created_at) <= max_age_seconds

def cleanup_old_nonces(older_than_seconds: int = 24 * 3600):
    now = int(time.time())
    cutoff = now - older_than_seconds
    conn = db_conn()
    conn.execute("DELETE FROM nonces WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()

def steam_openid_redirect(return_to_url: str):
    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": return_to_url,
        "openid.realm": BASE_URL,
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }
    return redirect(f"{STEAM_OPENID_ENDPOINT}?{urlencode(params)}")

def steam_verify_openid(args_dict: dict) -> bool:
    # Steam OpenID verification (check_authentication)
    verify_data = dict(args_dict)
    verify_data["openid.mode"] = "check_authentication"
    r = requests.post(STEAM_OPENID_ENDPOINT, data=verify_data, timeout=15)
    return ("is_valid:true" in r.text)

def extract_steamid_from_claimed_id(claimed_id: str) -> str:
    # claimed_id example: https://steamcommunity.com/openid/id/7656119...
    if not claimed_id:
        return ""
    parts = claimed_id.rstrip("/").split("/")
    if not parts:
        return ""
    steamid = parts[-1]
    if steamid.isdigit():
        return steamid
    return ""

def save_link(discord_user_id: str, steam_id: str):
    conn = db_conn()
    conn.execute(
        "INSERT OR REPLACE INTO links (discord_user_id, steam_id, linked_at) VALUES (?, ?, ?)",
        (str(discord_user_id), str(steam_id), int(time.time()))
    )
    conn.commit()
    conn.close()

def get_link(discord_user_id: str):
    conn = db_conn()
    row = conn.execute("SELECT * FROM links WHERE discord_user_id = ?", (str(discord_user_id),)).fetchone()
    conn.close()
    return row

def discord_add_role(discord_user_id: str, max_retries: int = 3):
    """
    Adds LINKED_ROLE_ID to a member in DISCORD_GUILD_ID.
    Handles Discord rate limits (429) by waiting Retry-After and retrying.
    """
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
    }

    for attempt in range(max_retries):
        r = requests.put(url, headers=headers, timeout=20)

        # Success is usually 204 No Content
        if r.status_code in (200, 201, 204):
            return True, "Role added"

        # Rate limited
        if r.status_code == 429:
            try:
                data = r.json()
            except Exception:
                data = {}
            retry_after = float(data.get("retry_after", 2.0))
            # small safety cap so we don't hang forever
            retry_after = min(retry_after, 10.0)
            time.sleep(retry_after)
            continue

        # Other errors
        return False, f"Discord role add failed: {r.status_code} {r.text}"

    return False, "Discord role add failed: Rate limited too long (429). Try again later."

# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def home():
    missing = missing_env()
    if missing:
        return (
            "Missing env vars: " + ", ".join(missing),
            500
        )

    return (
        "steam-link service is running ✅ "
        "(use /steam/start?discord_user_id=YOUR_DISCORD_ID )",
        200
    )

@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/steam/start")
def steam_start():
    missing = missing_env()
    if missing:
        return ("Missing env vars: " + ", ".join(missing), 500)

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return ("Provide a valid discord_user_id (numbers only).", 400)

    cleanup_old_nonces()

    state = build_state(discord_user_id)
    return_to = f"{BASE_URL}/steam/callback?state={state}"

    return steam_openid_redirect(return_to)

@app.get("/steam/callback")
def steam_callback():
    missing = missing_env()
    if missing:
        return ("Missing env vars: " + ", ".join(missing), 500)

    state = request.args.get("state", "")
    if not state:
        return ("Missing state.", 400)

    # Validate state signature + nonce
    try:
        payload = parse_state(state)
        discord_user_id = str(payload["d"])
        nonce = str(payload["n"])
    except (BadSignature, Exception) as e:
        return (f"Invalid state: {e}", 400)

    if not verify_nonce(nonce):
        return ("Invalid/expired state nonce. Re-run the link.", 400)

    # Verify OpenID response with Steam
    args_dict = request.args.to_dict(flat=True)
    if not steam_verify_openid(args_dict):
        return ("Steam OpenID verification failed. Try again.", 400)

    claimed_id = request.args.get("openid.claimed_id", "")
    steam_id = extract_steamid_from_claimed_id(claimed_id)
    if not steam_id:
        return ("Could not read SteamID from Steam response.", 400)

    # Save link
    save_link(discord_user_id, steam_id)

    # Try to add role (may be rate limited)
    ok, msg = discord_add_role(discord_user_id)
    if ok:
        return (f"Linked ✅ SteamID: {steam_id} and role added ✅", 200)

    # Still linked even if role failed
    return (f"Linked ✅ SteamID: {steam_id} BUT role add failed: {msg}", 200)

@app.get("/link/status")
def link_status():
    # Optional helper for debugging
    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return ("Provide discord_user_id=...", 400)

    row = get_link(discord_user_id)
    if not row:
        return jsonify({"linked": False})

    return jsonify({
        "linked": True,
        "discord_user_id": row["discord_user_id"],
        "steam_id": row["steam_id"],
        "linked_at": row["linked_at"],
    })

# ----------------------------
# Local run
# ----------------------------
if __name__ == "__main__":
    # Render sets PORT
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)
