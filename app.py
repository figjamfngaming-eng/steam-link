import os
import time
import hmac
import json
import base64
import secrets
import sqlite3
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect, abort, jsonify

app = Flask(__name__)

# ----------------------------
# Required Environment Variables
# ----------------------------
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")  # e.g. https://steam-link.onrender.com
STEAM_API_KEY = os.environ.get("STEAM_API_KEY", "")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "")
LINKED_ROLE_ID = os.environ.get("LINKED_ROLE_ID", "")
APP_SECRET = os.environ.get("APP_SECRET", "")  # random long string

# Optional: what role to assign after link
# Optional: where to store DB
DB_PATH = os.environ.get("DB_PATH", "linked.db")

STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login"

# Basic startup checks (helps you catch config mistakes instantly)
def _require_env():
    missing = []
    for k, v in [
        ("BASE_URL", BASE_URL),
        ("STEAM_API_KEY", STEAM_API_KEY),
        ("DISCORD_BOT_TOKEN", DISCORD_BOT_TOKEN),
        ("DISCORD_GUILD_ID", DISCORD_GUILD_ID),
        ("LINKED_ROLE_ID", LINKED_ROLE_ID),
        ("APP_SECRET", APP_SECRET),
    ]:
        if not v:
            missing.append(k)
    if missing:
        return f"Missing env vars: {', '.join(missing)}"
    if not BASE_URL.startswith("https://"):
        return "BASE_URL must start with https:// (Steam OpenID is strict)"
    return None


# ----------------------------
# SQLite storage
# ----------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS links (
            discord_user_id TEXT PRIMARY KEY,
            steam_id64 TEXT NOT NULL,
            persona_name TEXT,
            avatar_url TEXT,
            linked_at INTEGER NOT NULL
        )
        """
    )
    return conn


def save_link(discord_user_id: str, steam_id64: str, persona_name: str | None, avatar_url: str | None):
    conn = db()
    try:
        conn.execute(
            """
            INSERT INTO links(discord_user_id, steam_id64, persona_name, avatar_url, linked_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(discord_user_id) DO UPDATE SET
                steam_id64=excluded.steam_id64,
                persona_name=excluded.persona_name,
                avatar_url=excluded.avatar_url,
                linked_at=excluded.linked_at
            """,
            (discord_user_id, steam_id64, persona_name, avatar_url, int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()


def get_link(discord_user_id: str):
    conn = db()
    try:
        cur = conn.execute(
            "SELECT discord_user_id, steam_id64, persona_name, avatar_url, linked_at FROM links WHERE discord_user_id=?",
            (discord_user_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "discord_user_id": row[0],
            "steam_id64": row[1],
            "persona_name": row[2],
            "avatar_url": row[3],
            "linked_at": row[4],
        }
    finally:
        conn.close()


# ----------------------------
# Signed state helpers
# ----------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_state(discord_user_id: str) -> str:
    payload = {
        "duid": str(discord_user_id),
        "ts": int(time.time()),
        "nonce": secrets.token_hex(16),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(APP_SECRET.encode("utf-8"), raw, digestmod="sha256").digest()
    return _b64url(raw) + "." + _b64url(sig)


def read_state(state: str) -> dict:
    try:
        part_raw, part_sig = state.split(".", 1)
        raw = _b64url_decode(part_raw)
        sig = _b64url_decode(part_sig)
        expected = hmac.new(APP_SECRET.encode("utf-8"), raw, digestmod="sha256").digest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("bad signature")
        payload = json.loads(raw.decode("utf-8"))
        # expire after 15 minutes
        if int(time.time()) - int(payload.get("ts", 0)) > 15 * 60:
            raise ValueError("state expired")
        return payload
    except Exception as e:
        raise ValueError(f"invalid state: {e}")


# ----------------------------
# Steam OpenID validation
# ----------------------------
def steam_check_authentication(args: dict) -> bool:
    # Copy all openid.* fields and change mode to check_authentication
    data = {k: v for k, v in args.items() if k.startswith("openid.")}
    data["openid.mode"] = "check_authentication"

    r = requests.post(STEAM_OPENID_ENDPOINT, data=data, timeout=20)
    r.raise_for_status()
    return "is_valid:true" in r.text


def extract_steamid64_from_claimed_id(claimed_id: str) -> str | None:
    # claimed_id usually: https://steamcommunity.com/openid/id/7656119....
    if not claimed_id:
        return None
    parts = claimed_id.rstrip("/").split("/")
    if not parts:
        return None
    last = parts[-1]
    if last.isdigit():
        return last
    return None


def get_steam_profile(steam_id64: str) -> tuple[str | None, str | None]:
    # optional but nice for display
    if not STEAM_API_KEY:
        return None, None
    url = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
    params = {"key": STEAM_API_KEY, "steamids": steam_id64}
    r = requests.get(url, params=params, timeout=20)
    r.raise_for_status()
    data = r.json()
    players = data.get("response", {}).get("players", [])
    if not players:
        return None, None
    p = players[0]
    return p.get("personaname"), p.get("avatarfull")


# ----------------------------
# Discord API helpers (rate-limit safe)
# ----------------------------
DISCORD_API = "https://discord.com/api/v10"

def discord_headers():
    return {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "12oclockboyz-steam-link/1.0",
    }

def discord_add_role(discord_user_id: str):
    # PUT /guilds/{guild.id}/members/{user.id}/roles/{role.id}
    url = f"{DISCORD_API}/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"

    # Try a few times with backoff for 429
    for attempt in range(1, 6):
        resp = requests.put(url, headers=discord_headers(), timeout=20)

        if resp.status_code in (204, 201):
            return  # success

        if resp.status_code == 404:
            # user not in server or wrong IDs
            raise RuntimeError("Discord: user not found in guild (is the user in the server?)")

        if resp.status_code == 403:
            raise RuntimeError("Discord: forbidden. Bot missing permissions or role hierarchy issue.")

        if resp.status_code == 429:
            # rate limited - follow retry_after if present
            try:
                j = resp.json()
                retry_after = float(j.get("retry_after", 1.0))
            except Exception:
                retry_after = 1.0
            time.sleep(min(retry_after + 0.2, 10))
            continue

        # other errors
        raise RuntimeError(f"Discord add role failed: {resp.status_code} {resp.text}")

    raise RuntimeError("Discord rate-limited too long. Try again in 1 minute.")


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def home():
    err = _require_env()
    if err:
        return f"steam-link service running ✅ BUT CONFIG ERROR: {err}", 500
    return "steam-link service is running ✅ (use /steam/start?discord_user_id=...)", 200


@app.get("/steam/start")
def steam_start():
    err = _require_env()
    if err:
        return err, 500

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return "Missing or invalid discord_user_id", 400

    # Signed state lets callback know which Discord user is linking
    state = make_state(discord_user_id)

    return_to = f"{BASE_URL}/steam/callback"
    realm = BASE_URL

    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": return_to,
        "openid.realm": realm,
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
        "state": state,
    }

    return redirect(f"{STEAM_OPENID_ENDPOINT}?{urlencode(params)}", code=302)


@app.get("/steam/callback")
def steam_callback():
    err = _require_env()
    if err:
        return err, 500

    # Verify signed state
    state = request.args.get("state", "")
    try:
        payload = read_state(state)
        discord_user_id = payload["duid"]
    except ValueError as e:
        return f"Invalid state: {e}", 400

    # Validate OpenID response with Steam
    args = request.args.to_dict(flat=True)
    try:
        valid = steam_check_authentication(args)
    except Exception as e:
        return f"Steam validation request failed: {e}", 500

    if not valid:
        return "Steam authentication invalid.", 400

    claimed_id = request.args.get("openid.claimed_id", "")
    steam_id64 = extract_steamid64_from_claimed_id(claimed_id)
    if not steam_id64:
        return "Could not extract SteamID64.", 400

    # Get Steam display info (optional)
    persona_name = None
    avatar_url = None
    try:
        persona_name, avatar_url = get_steam_profile(steam_id64)
    except Exception:
        # If Steam API fails, still link using steam_id64
        pass

    # Save mapping
    save_link(discord_user_id, steam_id64, persona_name, avatar_url)

    # Add Discord role (rate-limit safe)
    try:
        discord_add_role(discord_user_id)
    except Exception as e:
        # Still show success for linking, but tell you role failed
        return (
            f"""
            <h2>Steam linked ✅</h2>
            <p><b>SteamID:</b> {steam_id64}</p>
            <p><b>Discord role:</b> FAILED to assign</p>
            <pre>{str(e)}</pre>
            <p>Fix bot permissions/role order or try again in a minute.</p>
            """,
            200,
        )

    # Success page
    display = persona_name or "Steam account"
    return f"""
        <h2>Linked ✅</h2>
        <p><b>{display}</b> is now linked to your Discord account.</p>
        <p><b>SteamID:</b> {steam_id64}</p>
        <p>You can close this tab and return to Discord.</p>
    """, 200


@app.get("/api/link_status")
def link_status():
    # optional endpoint for your discord bot to check if user is linked
    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return jsonify({"ok": False, "error": "invalid discord_user_id"}), 400

    link = get_link(discord_user_id)
    if not link:
        return jsonify({"ok": True, "linked": False}), 200
    return jsonify({"ok": True, "linked": True, "data": link}), 200


# Render uses $PORT
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
