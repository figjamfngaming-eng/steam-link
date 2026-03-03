import os
import time
import json
import sqlite3
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect, jsonify, make_response
from itsdangerous import URLSafeSerializer, BadSignature

# =========================
# ENV (set these in Render)
# =========================
BASE_URL = os.getenv("BASE_URL", "").strip().rstrip("/")
APP_SECRET = os.getenv("APP_SECRET", "").strip()  # random long string
ADMIN_KEY = os.getenv("ADMIN_KEY", "").strip()    # optional, for admin endpoints

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "").strip()
LINKED_ROLE_ID = os.getenv("LINKED_ROLE_ID", "").strip()

STEAM_API_KEY = os.getenv("STEAM_API_KEY", "").strip()  # optional for persona names

PORT = int(os.getenv("PORT", "10000"))
DB_PATH = os.getenv("DB_PATH", "steam_links.db").strip()

STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login"

# =========================
# Flask
# =========================
app = Flask(__name__)

# Signed state token (prevents spoofing discord_user_id)
serializer = None
if APP_SECRET:
    serializer = URLSafeSerializer(APP_SECRET, salt="steam-link-state-v1")


# =========================
# DB
# =========================
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def db_init():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS links (
            discord_user_id TEXT PRIMARY KEY,
            steam_id        TEXT NOT NULL,
            persona_name    TEXT,
            linked_at       INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def db_get_link(discord_user_id: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM links WHERE discord_user_id = ?", (str(discord_user_id),))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def db_get_by_steam(steam_id: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM links WHERE steam_id = ?", (str(steam_id),))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def db_upsert_link(discord_user_id: str, steam_id: str, persona_name: str | None):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO links(discord_user_id, steam_id, persona_name, linked_at)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(discord_user_id) DO UPDATE SET
            steam_id=excluded.steam_id,
            persona_name=excluded.persona_name,
            linked_at=excluded.linked_at
    """, (str(discord_user_id), str(steam_id), persona_name, now))
    conn.commit()
    conn.close()

def db_delete_link(discord_user_id: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM links WHERE discord_user_id = ?", (str(discord_user_id),))
    conn.commit()
    conn.close()


# =========================
# Helpers
# =========================
def missing_envs():
    missing = []
    if not BASE_URL:
        missing.append("BASE_URL")
    if not APP_SECRET:
        missing.append("APP_SECRET")
    if not DISCORD_BOT_TOKEN:
        missing.append("DISCORD_BOT_TOKEN")
    if not DISCORD_GUILD_ID:
        missing.append("DISCORD_GUILD_ID")
    if not LINKED_ROLE_ID:
        missing.append("LINKED_ROLE_ID")
    return missing

def require_env_or_explain():
    miss = missing_envs()
    if miss:
        return make_response(f"Missing env vars: {', '.join(miss)}", 500)
    return None

def build_state(discord_user_id: str) -> str:
    """
    Signed JSON blob so users cannot forge other people's Discord IDs.
    """
    if not serializer:
        raise RuntimeError("APP_SECRET not set (serializer unavailable)")

    payload = {
        "discord_user_id": str(discord_user_id),
        "nonce": secrets.token_urlsafe(16),
        "iat": int(time.time())
    }
    return serializer.dumps(payload)

def parse_state(state: str):
    if not serializer:
        raise RuntimeError("APP_SECRET not set (serializer unavailable)")
    try:
        payload = serializer.loads(state)
        # sanity check
        if not isinstance(payload, dict) or "discord_user_id" not in payload:
            raise ValueError("State payload invalid")
        return payload
    except BadSignature:
        raise ValueError("Invalid state signature")

def extract_steam_id_from_claimed_id(claimed_id: str) -> str | None:
    # claimed_id usually: https://steamcommunity.com/openid/id/<steamid>
    if not claimed_id:
        return None
    parts = claimed_id.rstrip("/").split("/")
    if parts and parts[-1].isdigit():
        return parts[-1]
    return None

def steam_openid_redirect_url(return_to: str) -> str:
    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": return_to,
        "openid.realm": BASE_URL,
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }
    return f"{STEAM_OPENID_ENDPOINT}?{urlencode(params)}"

def verify_openid_response(args: dict) -> bool:
    """
    Verify Steam OpenID response by calling check_authentication.
    """
    # Copy all openid.* params back and change mode
    data = {k: v for k, v in args.items() if k.startswith("openid.")}
    data["openid.mode"] = "check_authentication"
    try:
        r = requests.post(STEAM_OPENID_ENDPOINT, data=data, timeout=15)
        return "is_valid:true" in r.text
    except Exception:
        return False

def steam_get_persona_name(steam_id: str) -> str | None:
    if not STEAM_API_KEY:
        return None
    try:
        url = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
        r = requests.get(url, params={"key": STEAM_API_KEY, "steamids": steam_id}, timeout=15)
        r.raise_for_status()
        data = r.json()
        players = data.get("response", {}).get("players", [])
        if players:
            return players[0].get("personaname")
    except Exception:
        pass
    return None

def discord_headers():
    return {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json"
    }

def discord_add_role(discord_user_id: str) -> tuple[bool, str]:
    """
    Returns (ok, message). Handles 429 by retrying briefly.
    """
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"

    # Small retry loop (don’t hang forever on a web callback)
    for attempt in range(3):
        r = requests.put(url, headers=discord_headers(), timeout=15)

        if r.status_code in (204, 201):
            return True, "Role applied"

        if r.status_code == 429:
            # rate limited
            try:
                j = r.json()
                retry_after = float(j.get("retry_after", 1.0))
            except Exception:
                retry_after = 1.0

            # wait a bit then retry (cap wait)
            wait = min(max(retry_after, 1.0), 5.0)
            time.sleep(wait)
            continue

        # other errors
        return False, f"Discord role add failed ({r.status_code}): {r.text}"

    return False, "Discord rate limited (429). Try again in ~1 minute or run /status in Discord."

def discord_remove_role(discord_user_id: str) -> tuple[bool, str]:
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    try:
        r = requests.delete(url, headers=discord_headers(), timeout=15)
        if r.status_code in (204, 200):
            return True, "Role removed"
        if r.status_code == 429:
            return False, "Rate limited (429). Try again soon."
        return False, f"Discord role remove failed ({r.status_code}): {r.text}"
    except Exception as e:
        return False, f"Discord role remove failed: {e}"

def require_admin():
    if not ADMIN_KEY:
        return make_response("ADMIN_KEY not set on server.", 403)
    provided = request.headers.get("X-Admin-Key", "").strip()
    if provided != ADMIN_KEY:
        return make_response("Forbidden", 403)
    return None


# Init DB at import time (Flask 3 compatible)
db_init()


# =========================
# Routes
# =========================
@app.get("/")
def home():
    miss = missing_envs()
    if miss:
        return make_response(
            "steam-link service is running ✅ but missing env vars: " + ", ".join(miss),
            200
        )
    return make_response(
        "steam-link service is running ✅ (use /steam/start?discord_user_id=...)\n"
        "Bot uses /api/status?discord_user_id=... to check link.",
        200
    )

@app.get("/steam/start")
def steam_start():
    env_err = require_env_or_explain()
    if env_err:
        return env_err

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return make_response("Missing/invalid discord_user_id", 400)

    state = build_state(discord_user_id)
    return_to = f"{BASE_URL}/steam/callback?state={state}"
    return redirect(steam_openid_redirect_url(return_to), code=302)

@app.get("/steam/callback")
def steam_callback():
    env_err = require_env_or_explain()
    if env_err:
        return env_err

    state = request.args.get("state", "").strip()
    if not state:
        return make_response("Missing state", 400)

    # Parse signed state
    try:
        payload = parse_state(state)
        discord_user_id = payload["discord_user_id"]
    except Exception as e:
        return make_response(f"Invalid state: {e}", 400)

    # Verify OpenID response
    args = request.args.to_dict(flat=True)
    if not verify_openid_response(args):
        return make_response("Steam OpenID verification failed. Try again.", 400)

    claimed_id = args.get("openid.claimed_id", "")
    steam_id = extract_steam_id_from_claimed_id(claimed_id)
    if not steam_id:
        return make_response("Could not read SteamID from callback.", 400)

    # Alt detection: if this steam_id already linked to someone else, show warning but allow overwrite only via admin
    existing = db_get_by_steam(steam_id)
    if existing and existing["discord_user_id"] != str(discord_user_id):
        msg = (
            f"SteamID {steam_id} is already linked to Discord user {existing['discord_user_id']}.\n"
            f"Ask an admin to /force_link if this is you."
        )
        return make_response(msg, 409)

    persona = steam_get_persona_name(steam_id)
    db_upsert_link(discord_user_id, steam_id, persona)

    ok, role_msg = discord_add_role(discord_user_id)

    persona_txt = f" ({persona})" if persona else ""
    if ok:
        return make_response(
            f"Linked ✅ SteamID: {steam_id}{persona_txt}\n"
            f"Role: applied ✅\n"
            f"You can close this tab and go back to Discord.",
            200
        )
    else:
        # Link saved anyway; role might apply later via /status
        return make_response(
            f"Linked ✅ SteamID: {steam_id}{persona_txt}\n"
            f"Role: {role_msg}\n"
            f"(Link saved. If role didn’t apply, wait a bit and run /status in Discord.)",
            200
        )

@app.get("/api/status")
def api_status():
    env_err = require_env_or_explain()
    if env_err:
        return env_err

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return jsonify({"ok": False, "error": "Missing/invalid discord_user_id"}), 400

    link = db_get_link(discord_user_id)
    if not link:
        return jsonify({"ok": True, "linked": False})

    return jsonify({
        "ok": True,
        "linked": True,
        "discord_user_id": link["discord_user_id"],
        "steam_id": link["steam_id"],
        "persona_name": link.get("persona_name"),
        "linked_at": link["linked_at"],
    })

@app.post("/api/apply_role")
def api_apply_role():
    """
    Bot can call this when user runs /status in Discord to apply role later.
    """
    env_err = require_env_or_explain()
    if env_err:
        return env_err

    data = request.get_json(silent=True) or {}
    discord_user_id = str(data.get("discord_user_id", "")).strip()
    if not discord_user_id.isdigit():
        return jsonify({"ok": False, "error": "Missing/invalid discord_user_id"}), 400

    link = db_get_link(discord_user_id)
    if not link:
        return jsonify({"ok": True, "linked": False}), 200

    ok, msg = discord_add_role(discord_user_id)
    return jsonify({"ok": True, "linked": True, "role_applied": ok, "message": msg})

@app.post("/api/unlink")
def api_unlink():
    """
    Bot calls this for /unlink. Removes DB link and tries to remove role.
    """
    env_err = require_env_or_explain()
    if env_err:
        return env_err

    data = request.get_json(silent=True) or {}
    discord_user_id = str(data.get("discord_user_id", "")).strip()
    if not discord_user_id.isdigit():
        return jsonify({"ok": False, "error": "Missing/invalid discord_user_id"}), 400

    existed = db_get_link(discord_user_id) is not None
    if existed:
        db_delete_link(discord_user_id)

    ok, msg = discord_remove_role(discord_user_id)
    return jsonify({"ok": True, "unlinked": existed, "role_removed": ok, "message": msg})

@app.post("/api/force_link")
def api_force_link():
    """
    Admin endpoint to force a link (for alt/account fixes).
    Requires header: X-Admin-Key: <ADMIN_KEY>
    """
    env_err = require_env_or_explain()
    if env_err:
        return env_err

    admin_err = require_admin()
    if admin_err:
        return admin_err

    data = request.get_json(silent=True) or {}
    discord_user_id = str(data.get("discord_user_id", "")).strip()
    steam_id = str(data.get("steam_id", "")).strip()

    if not discord_user_id.isdigit():
        return jsonify({"ok": False, "error": "Invalid discord_user_id"}), 400
    if not steam_id.isdigit():
        return jsonify({"ok": False, "error": "Invalid steam_id"}), 400

    persona = steam_get_persona_name(steam_id)
    db_upsert_link(discord_user_id, steam_id, persona)

    ok, msg = discord_add_role(discord_user_id)
    return jsonify({"ok": True, "forced": True, "role_applied": ok, "message": msg})


if __name__ == "__main__":
    # Render expects 0.0.0.0 and PORT
    app.run(host="0.0.0.0", port=PORT)
