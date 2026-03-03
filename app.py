import os
import time
import json
import secrets
import urllib.parse
import requests
from flask import Flask, request, redirect, url_for, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)

# -------------------------
# ENV / CONFIG
# -------------------------
REQUIRED_ENV = ["BASE_URL", "DISCORD_BOT_TOKEN", "DISCORD_GUILD_ID", "LINKED_ROLE_ID", "APP_SECRET"]
missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
if missing:
    # Keep app alive but show a clear message
    @app.get("/")
    def _missing_env():
        return f"Missing env vars: {', '.join(missing)}", 500
else:
    pass

BASE_URL = os.getenv("BASE_URL", "").rstrip("/")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "")
LINKED_ROLE_ID = os.getenv("LINKED_ROLE_ID", "")
APP_SECRET = os.getenv("APP_SECRET", "")

# Signed state token (prevents tampering)
serializer = URLSafeTimedSerializer(APP_SECRET)

STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"

# Simple JSON storage (works on Render free without DB). You can swap to SQLite later.
LINK_FILE = "links.json"


def load_links():
    if not os.path.exists(LINK_FILE):
        return {}
    try:
        with open(LINK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_links(data: dict):
    with open(LINK_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def discord_add_role(discord_user_id: str):
    """Add LINKED_ROLE_ID to a member. Handles Discord 429 rate limits."""
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "steam-link/1.0"
    }

    # retry a few times on 429
    for _ in range(6):
        r = requests.put(url, headers=headers, timeout=20)
        if r.status_code in (204, 201):
            return True, None

        if r.status_code == 429:
            try:
                retry_after = r.json().get("retry_after", 2)
            except Exception:
                retry_after = 2
            time.sleep(float(retry_after) + 0.2)
            continue

        return False, f"{r.status_code} {r.text}"

    return False, "Rate limited too long (429). Try again."


def verify_steam_openid(args: dict) -> bool:
    """Verify OpenID response by sending check_authentication back to Steam."""
    verify_args = dict(args)
    verify_args["openid.mode"] = "check_authentication"

    r = requests.post(STEAM_OPENID_URL, data=verify_args, timeout=20)
    return "is_valid:true" in r.text


def steamid_from_claimed_id(claimed_id: str) -> str | None:
    # Example: https://steamcommunity.com/openid/id/7656119xxxxxxxxxx
    if not claimed_id:
        return None
    parts = claimed_id.rstrip("/").split("/")
    if not parts:
        return None
    last = parts[-1]
    return last if last.isdigit() else None


# -------------------------
# ROUTES
# -------------------------

@app.get("/")
def home():
    return (
        "steam-link service is running ✅ "
        "(use /steam/start?discord_user_id=...)", 200
    )


@app.get("/steam/start")
def steam_start():
    discord_user_id = request.args.get("discord_user_id", "").strip()

    if not discord_user_id.isdigit():
        return "Invalid discord_user_id. Must be digits.", 400

    # Create a nonce so each link attempt is unique
    nonce = secrets.token_urlsafe(16)

    # Sign state so it can't be edited
    state = serializer.dumps({"discord_user_id": discord_user_id, "nonce": nonce})

    # IMPORTANT: Put state into return_to so it comes back on callback
    return_to = f"{BASE_URL}/steam/callback?state={urllib.parse.quote(state)}"

    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": return_to,
        "openid.realm": BASE_URL,
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }

    redirect_url = STEAM_OPENID_URL + "?" + urllib.parse.urlencode(params)
    return redirect(redirect_url, code=302)


@app.get("/steam/callback")
def steam_callback():
    # 1) state must exist (it’s how we know which Discord user started this)
    state = request.args.get("state", "").strip()
    if not state:
        return "Invalid state: missing state. Please start again from /steam/start?discord_user_id=...", 400

    # 2) decode/verify state
    try:
        payload = serializer.loads(state, max_age=15 * 60)  # 15 min expiry
        discord_user_id = payload["discord_user_id"]
    except SignatureExpired:
        return "Link session expired. Please start again.", 400
    except BadSignature:
        return "Invalid state signature. Please start again.", 400
    except Exception as e:
        return f"Invalid state: {e}", 400

    # 3) verify OpenID response with Steam
    if not verify_steam_openid(request.args.to_dict(flat=True)):
        return "Steam OpenID verification failed. Please try again.", 400

    # 4) get SteamID
    claimed_id = request.args.get("openid.claimed_id", "")
    steam_id = steamid_from_claimed_id(claimed_id)
    if not steam_id:
        return "Could not read SteamID from OpenID response.", 400

    # 5) store mapping
    links = load_links()
    links[str(discord_user_id)] = {"steam_id": steam_id, "linked_at": int(time.time())}
    save_links(links)

    # 6) add Discord role (rate-limit safe)
    ok, err = discord_add_role(str(discord_user_id))
    if not ok:
        # Still linked, but role failed
        return (
            f"Linked ✅ SteamID: {steam_id}\n"
            f"BUT role add failed: {err}\n"
            f"Try again later or re-run the link.",
            200
        )

    return f"Linked ✅ SteamID: {steam_id} (role granted)", 200


@app.get("/api/linked/<discord_user_id>")
def api_linked(discord_user_id: str):
    links = load_links()
    return jsonify(links.get(str(discord_user_id), {})), 200


if __name__ == "__main__":
    # Local dev
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
