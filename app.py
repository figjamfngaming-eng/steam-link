import os
import sqlite3
import time
import urllib.parse
import requests
from flask import Flask, request, redirect, abort

app = Flask(__name__)

# ---------- ENV ----------
DB = os.environ.get("LINK_DB", "steam_links.db")

STEAM_API_KEY = os.environ["STEAM_API_KEY"]                 # required
DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]         # required
DISCORD_GUILD_ID = int(os.environ["DISCORD_GUILD_ID"])      # required
LINKED_ROLE_ID = int(os.environ["LINKED_ROLE_ID"])          # required
BASE_URL = os.environ["BASE_URL"].rstrip("/")               # required (must match your render domain)

MXB_APP_ID = 655500  # MX Bikes
STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login"

# How long a link session is valid after /steam/start
PENDING_TTL_SECONDS = 15 * 60


# ---------- DB ----------
def db_init():
    with sqlite3.connect(DB) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS pending(
                state TEXT PRIMARY KEY,
                discord_user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS linked(
                discord_user_id INTEGER PRIMARY KEY,
                steamid64 TEXT NOT NULL,
                linked_at INTEGER NOT NULL
            )
            """
        )
        con.commit()


def new_state() -> str:
    return os.urandom(16).hex()


# ---------- DISCORD HELPERS ----------
def discord_add_role(discord_user_id: int, max_retries: int = 5) -> tuple[bool, str]:
    """
    Adds the Linked role to a user. Handles 429 rate limits with backoff.
    Returns (success, message).
    """
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}

    for attempt in range(1, max_retries + 1):
        r = requests.put(url, headers=headers, timeout=20)

        if r.status_code in (204, 201):
            return True, "Role assigned"

        # Rate limited
        if r.status_code == 429:
            try:
                data = r.json()
            except Exception:
                data = {}

            retry_after = data.get("retry_after")
            if retry_after is None:
                # fallback: exponential backoff
                retry_after = min(2 ** attempt, 30)

            time.sleep(float(retry_after) + 0.25)
            continue

        # Other error (permissions, wrong ids, etc.)
        return False, f"Discord role add failed: {r.status_code} {r.text}"

    return False, "Discord role add failed: rate limited too long (try again in 1–2 minutes)"


def discord_dm(discord_user_id: int, content: str) -> None:
    """
    Best-effort DM. If DMs are closed, do nothing.
    """
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}

    # Create DM channel
    r1 = requests.post(
        "https://discord.com/api/v10/users/@me/channels",
        headers=headers,
        json={"recipient_id": str(discord_user_id)},
        timeout=20,
    )
    if r1.status_code not in (200, 201):
        return

    channel_id = r1.json().get("id")
    if not channel_id:
        return

    requests.post(
        f"https://discord.com/api/v10/channels/{channel_id}/messages",
        headers=headers,
        json={"content": content},
        timeout=20,
    )


# ---------- STEAM HELPERS ----------
def steamid_from_openid_claimed_id(claimed_id: str) -> str | None:
    # https://steamcommunity.com/openid/id/<steamid64>
    parts = claimed_id.rstrip("/").split("/")
    if parts and parts[-1].isdigit():
        return parts[-1]
    return None


def owns_mxb(steamid64: str) -> bool:
    """
    Checks if the Steam account owns MX Bikes via GetOwnedGames.
    NOTE: requires the user's Game Details visibility to allow access.
    """
    url = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/"
    params = {
        "key": STEAM_API_KEY,
        "steamid": steamid64,
        "include_appinfo": 0,
        "include_played_free_games": 1,
        "format": "json",
    }
    r = requests.get(url, params=params, timeout=25)
    if r.status_code != 200:
        return False

    data = r.json()
    games = data.get("response", {}).get("games", [])
    return any(g.get("appid") == MXB_APP_ID for g in games)


def verify_openid_response(args: dict) -> bool:
    """
    Validates OpenID response with Steam by calling check_authentication.
    """
    verify_args = dict(args)
    verify_args["openid.mode"] = "check_authentication"
    vr = requests.post(STEAM_OPENID_ENDPOINT, data=verify_args, timeout=25)
    return vr.status_code == 200 and "is_valid:true" in vr.text


# ---------- ROUTES ----------
@app.get("/")
def home():
    # Helpful non-404 so you know the service is alive
    return "steam-link service is running ✅ (use /steam/start?discord_user_id=...)", 200


@app.get("/steam/start")
def steam_start():
    """
    Called from the bot: /steam/start?discord_user_id=123
    Creates a state token and redirects user to Steam OpenID login.
    """
    discord_user_id = request.args.get("discord_user_id", type=int)
    if not discord_user_id:
        abort(400, "Missing discord_user_id")

    state = new_state()
    now = int(time.time())

    with sqlite3.connect(DB) as con:
        con.execute(
            "INSERT INTO pending(state, discord_user_id, created_at) VALUES(?,?,?)",
            (state, discord_user_id, now),
        )
        con.commit()

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

    return redirect(STEAM_OPENID_ENDPOINT + "?" + urllib.parse.urlencode(params))


@app.get("/steam/callback")
def steam_callback():
    """
    Steam redirects here. We validate OpenID response by calling Steam endpoint with check_authentication.
    Then ownership check, then assign role in Discord.
    """
    state = request.args.get("state")
    if not state:
        abort(400, "Missing state")

    # Look up pending request
    with sqlite3.connect(DB) as con:
        row = con.execute(
            "SELECT discord_user_id, created_at FROM pending WHERE state=?",
            (state,),
        ).fetchone()

    if not row:
        abort(400, "Invalid/expired state. Run /link_steam again.")

    discord_user_id, created_at = int(row[0]), int(row[1])
    if int(time.time()) - created_at > PENDING_TTL_SECONDS:
        abort(400, "Link expired. Run /link_steam again.")

    # Validate OpenID assertion
    if not verify_openid_response(request.args.to_dict(flat=True)):
        abort(400, "Steam login verification failed.")

    claimed_id = request.args.get("openid.claimed_id", "")
    steamid64 = steamid_from_openid_claimed_id(claimed_id)
    if not steamid64:
        abort(400, "Could not read SteamID from Steam response.")

    # Ownership check for MX Bikes
    if not owns_mxb(steamid64):
        msg = (
            "❌ Link failed: could not verify MX Bikes ownership.\n\n"
            "Fix: Steam → Profile → Privacy Settings → **Game Details** = **Public**, then run /link_steam again."
        )
        discord_dm(discord_user_id, msg)
        return msg, 403

    now = int(time.time())

    # Save link + cleanup pending
    with sqlite3.connect(DB) as con:
        con.execute(
            "INSERT OR REPLACE INTO linked(discord_user_id, steamid64, linked_at) VALUES(?,?,?)",
            (discord_user_id, steamid64, now),
        )
        con.execute("DELETE FROM pending WHERE state=?", (state,))
        con.commit()

    # If already has role, skip assigning again (reduces rate-limit hits)
    # We can't check roles without another API call, so we just try once with safe retry.
    ok, detail = discord_add_role(discord_user_id)

    if ok:
        discord_dm(discord_user_id, "✅ Steam linked and MX Bikes ownership verified. You now have access to races.")
        return "Linked ✅ You can close this tab and return to Discord.", 200

    # If role assignment fails (rate limit etc), DO NOT 500. Still linked in DB.
    discord_dm(
        discord_user_id,
        "✅ Steam linked and MX Bikes ownership verified.\n"
        "⚠️ I couldn’t assign your Linked Rider role right now (Discord rate limit).\n"
        "Wait 1–2 minutes and run /link_steam again ONCE, or ask staff to manually assign Linked Rider.",
    )
    return f"Linked ✅ (role assignment pending: {detail})", 200


# ---------- MAIN ----------
if __name__ == "__main__":
    db_init()
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
