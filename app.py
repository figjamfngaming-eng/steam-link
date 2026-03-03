import os
import re
import json
import time
import sqlite3
from urllib.parse import urlencode

import requests
from flask import Flask, request, redirect, url_for, abort
from itsdangerous import URLSafeSerializer, BadSignature


# -----------------------------
# Config / ENV
# -----------------------------
BASE_URL = os.getenv("BASE_URL", "").strip().rstrip("/")
APP_SECRET = os.getenv("APP_SECRET", "").strip()

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "").strip()
LINKED_ROLE_ID = os.getenv("LINKED_ROLE_ID", "").strip()

ADMIN_KEY = os.getenv("ADMIN_KEY", "").strip()

STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"

DB_FILE = "links.db"
PENDING_FILE = "pending_roles.json"

app = Flask(__name__)


def missing_env():
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


def get_serializer():
    # deterministic signer for state
    return URLSafeSerializer(APP_SECRET, salt="steam-link-state")


# -----------------------------
# DB
# -----------------------------
def db_init():
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS links (
            discord_user_id TEXT PRIMARY KEY,
            steam_id TEXT NOT NULL,
            linked_at INTEGER NOT NULL
        )
        """
    )
    con.commit()
    con.close()


def db_set_link(discord_user_id: str, steam_id: str):
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO links(discord_user_id, steam_id, linked_at)
        VALUES(?,?,?)
        ON CONFLICT(discord_user_id) DO UPDATE SET
            steam_id=excluded.steam_id,
            linked_at=excluded.linked_at
        """,
        (str(discord_user_id), str(steam_id), int(time.time())),
    )
    con.commit()
    con.close()


def db_get_link(discord_user_id: str):
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    cur.execute("SELECT steam_id, linked_at FROM links WHERE discord_user_id=?", (str(discord_user_id),))
    row = cur.fetchone()
    con.close()
    return row


# -----------------------------
# Pending role queue
# -----------------------------
def load_pending():
    if not os.path.exists(PENDING_FILE):
        return []
    try:
        with open(PENDING_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []


def save_pending(items):
    with open(PENDING_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)


def queue_role(discord_user_id: str, delay_seconds: float = 10.0, reason: str = ""):
    pending = load_pending()
    pending.append(
        {
            "discord_user_id": str(discord_user_id),
            "next_try": time.time() + float(delay_seconds),
            "tries": 0,
            "reason": reason,
        }
    )
    save_pending(pending)


# -----------------------------
# Discord role grant
# -----------------------------
def discord_add_role(discord_user_id: str):
    """
    Returns (ok: bool, msg: str|None)
    Uses queue on rate limit 429 instead of spamming.
    """
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "steam-link/1.0",
    }

    try:
        r = requests.put(url, headers=headers, timeout=25)
    except Exception as e:
        queue_role(discord_user_id, delay_seconds=30, reason=f"request_error:{e}")
        return False, f"Discord request error. Queued retry."

    if r.status_code in (204, 201):
        return True, None

    if r.status_code == 429:
        # Discord rate limit response includes retry_after seconds (often fractional)
        try:
            retry_after = float(r.json().get("retry_after", 5))
        except Exception:
            retry_after = 5.0
        queue_role(discord_user_id, delay_seconds=retry_after + 1.0, reason="rate_limited")
        return False, f"Rate limited (429). Queued role grant in ~{int(retry_after)}s."

    # Other common issues:
    # 403 = missing perms / role hierarchy
    # 404 = user not in guild / wrong IDs
    msg = f"Role add failed: {r.status_code} {r.text}"
    # Retry a couple times for transient errors
    if r.status_code >= 500:
        queue_role(discord_user_id, delay_seconds=30, reason=f"discord_{r.status_code}")
        return False, f"{msg}. Queued retry."
    return False, msg


# -----------------------------
# Steam OpenID helpers
# -----------------------------
STEAMID_RE = re.compile(r"^https?://steamcommunity\.com/openid/id/(\d+)$")


def build_openid_redirect(state_token: str):
    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": f"{BASE_URL}{url_for('steam_callback')}?state={state_token}",
        "openid.realm": f"{BASE_URL}/",
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }
    return f"{STEAM_OPENID_URL}?{urlencode(params)}"


def verify_openid_response(args_dict):
    # per Steam OpenID verification: POST back with openid.mode=check_authentication
    data = dict(args_dict)
    data["openid.mode"] = "check_authentication"
    r = requests.post(STEAM_OPENID_URL, data=data, timeout=25)
    return r.status_code == 200 and "is_valid:true" in r.text


def extract_steamid(claimed_id: str):
    if not claimed_id:
        return None
    m = STEAMID_RE.match(claimed_id.strip())
    if not m:
        return None
    return m.group(1)


# -----------------------------
# Routes
# -----------------------------
@app.before_first_request
def _startup():
    db_init()


@app.get("/")
def home():
    miss = missing_env()
    if miss:
        return (
            "Missing env vars: " + ", ".join(miss),
            500,
        )

    # Show basic instructions + example link format
    return (
        'steam-link service is running ✅ '
        "(use /steam/start?discord_user_id=YOUR_ID)\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.get("/steam/start")
def steam_start():
    miss = missing_env()
    if miss:
        return ("Missing env vars: " + ", ".join(miss), 500)

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return ("Missing/invalid discord_user_id", 400)

    # Signed state prevents tampering + fixes your “invalid state” unpack errors
    s = get_serializer()
    payload = {
        "d": discord_user_id,
        "t": int(time.time()),
        "n": os.urandom(8).hex(),
    }
    state_token = s.dumps(payload)

    return redirect(build_openid_redirect(state_token), code=302)


@app.get("/steam/callback")
def steam_callback():
    miss = missing_env()
    if miss:
        return ("Missing env vars: " + ", ".join(miss), 500)

    # Validate state
    state_token = request.args.get("state", "").strip()
    if not state_token:
        return ("Invalid state: missing state", 400)

    s = get_serializer()
    try:
        payload = s.loads(state_token)
    except BadSignature:
        return ("Invalid state: bad signature", 400)

    discord_user_id = str(payload.get("d", "")).strip()
    if not discord_user_id.isdigit():
        return ("Invalid state: missing discord id", 400)

    # Verify OpenID response with Steam
    ok = verify_openid_response(request.args.to_dict(flat=True))
    if not ok:
        return ("Steam verification failed. Try again.", 400)

    # Extract SteamID
    claimed = request.args.get("openid.claimed_id", "")
    steam_id = extract_steamid(claimed)
    if not steam_id:
        return ("Could not read SteamID from response.", 400)

    # Store link
    db_set_link(discord_user_id, steam_id)

    # Try to grant role (queue if rate limited)
    role_ok, role_msg = discord_add_role(discord_user_id)

    if role_ok:
        return (
            f"Linked ✅ SteamID: {steam_id} and role granted ✅",
            200,
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    # Not fatal — linking succeeded even if role grant didn’t
    return (
        f"Linked ✅ SteamID: {steam_id} BUT role add failed: {role_msg}\n"
        f"If it was rate limited, wait a bit and run /admin/process-pending (or try link again later).",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.get("/admin/process-pending")
def process_pending():
    # Protect with ADMIN_KEY if set
    if ADMIN_KEY:
        if request.args.get("key", "") != ADMIN_KEY:
            return ("Forbidden", 403)

    pending = load_pending()
    if not pending:
        return ("No pending items", 200)

    now = time.time()
    new_pending = []
    processed = 0
    deferred = 0

    for item in pending:
        try:
            discord_user_id = str(item.get("discord_user_id", "")).strip()
            next_try = float(item.get("next_try", 0))
            tries = int(item.get("tries", 0))
        except Exception:
            continue

        if not discord_user_id.isdigit():
            continue

        if next_try > now:
            new_pending.append(item)
            deferred += 1
            continue

        ok, msg = discord_add_role(discord_user_id)
        if ok:
            processed += 1
            continue

        # If it queued due to 429, discord_add_role already wrote a new queue entry.
        # We avoid duplicating. But for non-429 errors, retry a few times.
        if msg and "Queued" in msg:
            processed += 0
            continue

        tries += 1
        if tries < 5:
            item["tries"] = tries
            item["next_try"] = now + (10 * tries)
            new_pending.append(item)

    save_pending(new_pending)
    return (f"Processed: {processed} | Deferred: {deferred} | Remaining: {len(new_pending)}", 200)


@app.get("/admin/check")
def admin_check():
    # optional: check if a discord user is linked
    if ADMIN_KEY:
        if request.args.get("key", "") != ADMIN_KEY:
            return ("Forbidden", 403)

    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return ("Missing/invalid discord_user_id", 400)

    row = db_get_link(discord_user_id)
    if not row:
        return ("Not linked", 200)

    steam_id, linked_at = row
    return (f"Linked ✅ SteamID: {steam_id} | linked_at: {linked_at}", 200)


# -----------------------------
# Render entrypoint
# -----------------------------
if __name__ == "__main__":
    # Render sets PORT
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)
