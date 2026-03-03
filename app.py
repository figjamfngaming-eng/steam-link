# app.py — FULL FIX (Flask 3 compatible)
# Steam OpenID linking service + link status API + unlink + admin force_link
# + safe Discord role add (handles 429 + cooldown, won’t crash)
#
# Required ENV (Render):
#   BASE_URL            e.g. https://steam-link.onrender.com
#   APP_SECRET          long random string (signs state)
#
# Optional ENV (for auto role add):
#   DISCORD_BOT_TOKEN
#   DISCORD_GUILD_ID
#   LINKED_ROLE_ID
#
# Optional ENV (admin endpoints protection):
#   ADMIN_KEY           long random string
#
# Optional ENV (persona name in /link/status):
#   STEAM_API_KEY       (Steam Web API key)

import os
import time
import sqlite3
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect, jsonify, make_response
from itsdangerous import URLSafeSerializer, BadSignature

# -----------------------------
# ENV
# -----------------------------
BASE_URL = os.getenv("BASE_URL", "").strip().rstrip("/")
APP_SECRET = os.getenv("APP_SECRET", "").strip()

ADMIN_KEY = os.getenv("ADMIN_KEY", "").strip()

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "").strip()
LINKED_ROLE_ID = os.getenv("LINKED_ROLE_ID", "").strip()

STEAM_API_KEY = os.getenv("STEAM_API_KEY", "").strip()

PORT = int(os.getenv("PORT", "10000"))
DB_PATH = os.getenv("DB_PATH", "steam_links.db")

STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login"

app = Flask(__name__)

# -----------------------------
# DB
# -----------------------------
def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS links (
            discord_user_id TEXT PRIMARY KEY,
            steam_id TEXT NOT NULL,
            linked_at INTEGER NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS role_attempts (
            discord_user_id TEXT PRIMARY KEY,
            last_attempt INTEGER NOT NULL,
            last_status INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


db_init()  # Flask 3 compatible (no before_first_request)

# -----------------------------
# Helpers
# -----------------------------
def missing_required_env():
    missing = []
    if not BASE_URL:
        missing.append("BASE_URL")
    if not APP_SECRET:
        missing.append("APP_SECRET")
    return missing


def srlzr():
    return URLSafeSerializer(APP_SECRET, salt="steam-link-state")


def make_state(discord_user_id: str) -> str:
    payload = {"d": str(discord_user_id), "t": int(time.time())}
    return srlzr().dumps(payload)


def read_state(state: str) -> str:
    payload = srlzr().loads(state)  # may raise BadSignature
    # expire after 15 minutes
    if int(time.time()) - int(payload.get("t", 0)) > 15 * 60:
        raise BadSignature("state expired")
    duid = str(payload.get("d", "")).strip()
    if not duid.isdigit():
        raise BadSignature("bad discord id in state")
    return duid


def verify_openid_with_steam(args: dict) -> bool:
    # Send check_authentication back to Steam OpenID endpoint
    data = {k: v for k, v in args.items() if k.startswith("openid.")}
    data["openid.mode"] = "check_authentication"
    r = requests.post(STEAM_OPENID_ENDPOINT, data=data, timeout=20)
    return r.status_code == 200 and "is_valid:true" in r.text


def extract_steamid64(claimed_id: str) -> str | None:
    # https://steamcommunity.com/openid/id/<steamid64>
    if not claimed_id:
        return None
    parts = claimed_id.rstrip("/").split("/")
    if not parts:
        return None
    last = parts[-1]
    return last if last.isdigit() else None


def save_link(discord_user_id: str, steam_id: str):
    conn = db_conn()
    conn.execute(
        """
        INSERT INTO links (discord_user_id, steam_id, linked_at)
        VALUES (?, ?, ?)
        ON CONFLICT(discord_user_id) DO UPDATE SET
          steam_id=excluded.steam_id,
          linked_at=excluded.linked_at
        """,
        (str(discord_user_id), str(steam_id), int(time.time())),
    )
    conn.commit()
    conn.close()


def delete_link(discord_user_id: str):
    conn = db_conn()
    conn.execute("DELETE FROM links WHERE discord_user_id=?", (str(discord_user_id),))
    conn.execute("DELETE FROM role_attempts WHERE discord_user_id=?", (str(discord_user_id),))
    conn.commit()
    conn.close()


def get_link(discord_user_id: str):
    conn = db_conn()
    row = conn.execute(
        "SELECT discord_user_id, steam_id, linked_at FROM links WHERE discord_user_id=?",
        (str(discord_user_id),),
    ).fetchone()
    conn.close()
    return row


def steam_persona_name(steam_id64: str) -> str | None:
    if not STEAM_API_KEY:
        return None
    url = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
    try:
        r = requests.get(url, params={"key": STEAM_API_KEY, "steamids": steam_id64}, timeout=20)
        if r.status_code != 200:
            return None
        data = r.json()
        players = data.get("response", {}).get("players", [])
        if not players:
            return None
        return players[0].get("personaname")
    except Exception:
        return None


# -----------------------------
# Discord role add (optional)
# -----------------------------
def discord_config_ok() -> bool:
    return bool(DISCORD_BOT_TOKEN and DISCORD_GUILD_ID and LINKED_ROLE_ID)


def role_attempt_allowed(discord_user_id: str, cooldown_seconds: int = 180) -> bool:
    """Prevent hammering Discord API (helps avoid global 429)."""
    conn = db_conn()
    row = conn.execute(
        "SELECT last_attempt FROM role_attempts WHERE discord_user_id=?",
        (str(discord_user_id),),
    ).fetchone()
    conn.close()
    if not row:
        return True
    last = int(row["last_attempt"])
    return (int(time.time()) - last) >= cooldown_seconds


def set_role_attempt(discord_user_id: str, status_code: int):
    conn = db_conn()
    conn.execute(
        """
        INSERT INTO role_attempts (discord_user_id, last_attempt, last_status)
        VALUES (?, ?, ?)
        ON CONFLICT(discord_user_id) DO UPDATE SET
          last_attempt=excluded.last_attempt,
          last_status=excluded.last_status
        """,
        (str(discord_user_id), int(time.time()), int(status_code)),
    )
    conn.commit()
    conn.close()


def discord_add_role(discord_user_id: str) -> tuple[bool, str]:
    """
    Adds LINKED_ROLE_ID to user in DISCORD_GUILD_ID.
    Safe: handles 429, returns message, never crashes app.
    """
    if not discord_config_ok():
        return False, "Discord role add not configured (missing DISCORD_* env vars)."

    if not role_attempt_allowed(discord_user_id):
        return False, "Role add skipped (cooldown active to avoid rate limits)."

    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}

    r = requests.put(url, headers=headers, timeout=20)

    if r.status_code in (204, 201):
        set_role_attempt(discord_user_id, 204)
        return True, "Role granted ✅"

    if r.status_code == 429:
        # Don’t retry spam here. Let cooldown handle it; user can relink later.
        set_role_attempt(discord_user_id, 429)
        try:
            retry_after = r.json().get("retry_after", 5)
        except Exception:
            retry_after = 5
        return False, f"Discord rate limited (429). Retry after ~{retry_after}s."

    # Common errors:
    # 403: bot lacks Manage Roles or role hierarchy wrong
    # 404: user not in guild or wrong IDs
    set_role_attempt(discord_user_id, r.status_code)
    return False, f"Discord role add failed: {r.status_code} {r.text[:200]}"


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def home():
    miss = missing_required_env()
    if miss:
        return make_response(
            "steam-link service running ✅\n"
            f"CONFIG ERROR: Missing env vars: {', '.join(miss)}\n",
            500,
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    return make_response(
        "steam-link service is running ✅\n\n"
        "Link format:\n"
        f"{BASE_URL}/steam/start?discord_user_id=YOUR_DISCORD_ID\n\n"
        "Bot status check:\n"
        f"{BASE_URL}/link/status?discord_user_id=YOUR_DISCORD_ID\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.get("/steam/start")
def steam_start():
    miss = missing_required_env()
    if miss:
        return make_response(f"Missing env vars: {', '.join(miss)}", 500)

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return make_response("Missing/invalid discord_user_id", 400)

    state = make_state(discord_user_id)

    # IMPORTANT: include state in return_to so it always comes back
    return_to = f"{BASE_URL}/steam/callback?state={state}"
    realm = BASE_URL

    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": return_to,
        "openid.realm": realm,
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }

    return redirect(STEAM_OPENID_ENDPOINT + "?" + urlencode(params), code=302)


@app.get("/steam/callback")
def steam_callback():
    miss = missing_required_env()
    if miss:
        return make_response(f"Missing env vars: {', '.join(miss)}", 500)

    state = request.args.get("state", "").strip()
    if not state:
        return make_response("Missing state. Start again from /steam/start?discord_user_id=...", 400)

    try:
        discord_user_id = read_state(state)
    except BadSignature as e:
        return make_response(f"Invalid state: {e}", 400)

    args = request.args.to_dict(flat=True)

    # Verify OpenID response with Steam
    try:
        if not verify_openid_with_steam(args):
            return make_response("Steam OpenID verification failed. Start again.", 400)
    except Exception as e:
        return make_response(f"Steam verification request failed: {e}", 500)

    steam_id = extract_steamid64(args.get("openid.claimed_id", ""))
    if not steam_id:
        return make_response("Could not extract SteamID64 from Steam response.", 400)

    # Save link
    save_link(discord_user_id, steam_id)

    # Attempt role grant (optional)
    role_ok, role_msg = discord_add_role(discord_user_id)
    if role_ok:
        return make_response(
            f"Linked ✅ SteamID: {steam_id}\n{role_msg}\nYou can close this tab and return to Discord.",
            200,
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    return make_response(
        f"Linked ✅ SteamID: {steam_id}\n"
        f"Role: {role_msg}\n"
        f"(Link saved. If role didn’t apply, wait a bit and run /status in Discord.)",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.get("/link/status")
def link_status():
    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return jsonify({"linked": False, "error": "invalid_discord_user_id"}), 400

    row = get_link(discord_user_id)
    if not row:
        return jsonify({"linked": False}), 200

    steam_id = row["steam_id"]
    mx_name = steam_persona_name(steam_id)  # optional (needs STEAM_API_KEY)

    return jsonify(
        {
            "linked": True,
            "discord_user_id": row["discord_user_id"],
            "steam_id": steam_id,
            "mx_name": mx_name,  # Steam display name
            "linked_at": row["linked_at"],
        }
    ), 200


@app.get("/unlink")
def unlink():
    # User self-unlink: /unlink?discord_user_id=...
    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return make_response("Invalid discord_user_id", 400)
    delete_link(discord_user_id)
    return make_response("Unlinked ✅", 200)


@app.get("/admin/force_link")
def admin_force_link():
    # Protect with ADMIN_KEY if set
    if ADMIN_KEY and request.args.get("key", "") != ADMIN_KEY:
        return make_response("Forbidden", 403)

    discord_user_id = request.args.get("discord_user_id", "").strip()
    steam_id = request.args.get("steam_id", "").strip()

    if not discord_user_id.isdigit() or not steam_id.isdigit():
        return make_response("Invalid discord_user_id or steam_id", 400)

    save_link(discord_user_id, steam_id)

    role_ok, role_msg = discord_add_role(discord_user_id)
    return make_response(
        f"Force linked ✅\nDiscord: {discord_user_id}\nSteamID: {steam_id}\nRole: {role_msg}",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.get("/health")
def health():
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
