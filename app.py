import os
import sqlite3
import time
import urllib.parse
import requests
from flask import Flask, request, redirect, abort

app = Flask(__name__)

DB = os.environ.get("LINK_DB", "steam_links.db")

STEAM_API_KEY = os.environ["STEAM_API_KEY"]          # required
DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]  # required (kept private on server)
DISCORD_GUILD_ID = int(os.environ["DISCORD_GUILD_ID"])
LINKED_ROLE_ID = int(os.environ["LINKED_ROLE_ID"])

BASE_URL = os.environ["BASE_URL"].rstrip("/")        # e.g. https://your-app.onrender.com
MXB_APP_ID = 655500  # MX Bikes :contentReference[oaicite:3]{index=3}

STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login"


def db_init():
    with sqlite3.connect(DB) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS pending(
            state TEXT PRIMARY KEY,
            discord_user_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )""")
        con.execute("""
        CREATE TABLE IF NOT EXISTS linked(
            discord_user_id INTEGER PRIMARY KEY,
            steamid64 TEXT NOT NULL,
            linked_at INTEGER NOT NULL
        )""")
        con.commit()


def new_state() -> str:
    # good enough for this use-case
    return os.urandom(16).hex()


def discord_add_role(discord_user_id: int):
    url = f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}/members/{discord_user_id}/roles/{LINKED_ROLE_ID}"
    r = requests.put(url, headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=15)
    if r.status_code not in (204, 201):
        raise RuntimeError(f"Discord add role failed: {r.status_code} {r.text}")


def discord_dm(discord_user_id: int, content: str):
    # create DM channel
    r1 = requests.post(
        "https://discord.com/api/v10/users/@me/channels",
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"},
        json={"recipient_id": str(discord_user_id)},
        timeout=15
    )
    if r1.status_code not in (200, 201):
        return  # DMs might be closed; not fatal
    channel_id = r1.json()["id"]

    # send message
    requests.post(
        f"https://discord.com/api/v10/channels/{channel_id}/messages",
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"},
        json={"content": content},
        timeout=15
    )


def steamid_from_openid_claimed_id(claimed_id: str) -> str | None:
    # claimed_id looks like: https://steamcommunity.com/openid/id/<steamid64>
    parts = claimed_id.rstrip("/").split("/")
    if parts and parts[-1].isdigit():
        return parts[-1]
    return None


def owns_mxb(steamid64: str) -> bool:
    # Requires profile game details to be public in many cases
    url = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/"
    params = {
        "key": STEAM_API_KEY,
        "steamid": steamid64,
        "include_appinfo": 0,
        "include_played_free_games": 1,
        "format": "json"
    }
    r = requests.get(url, params=params, timeout=20)
    if r.status_code != 200:
        return False

    data = r.json()
    games = data.get("response", {}).get("games", [])
    return any(g.get("appid") == MXB_APP_ID for g in games)


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
        con.execute("INSERT INTO pending(state, discord_user_id, created_at) VALUES(?,?,?)", (state, discord_user_id, now))
        con.commit()

    # Build OpenID redirect
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
        row = con.execute("SELECT discord_user_id, created_at FROM pending WHERE state=?", (state,)).fetchone()
    if not row:
        abort(400, "Invalid/expired state")

    discord_user_id, created_at = int(row[0]), int(row[1])
    if int(time.time()) - created_at > 15 * 60:
        abort(400, "Link expired. Run /link_steam again.")

    # Verify OpenID assertion with Steam (check_authentication)
    args = dict(request.args)
    args["openid.mode"] = "check_authentication"

    verify = requests.post(STEAM_OPENID_ENDPOINT, data=args, timeout=20)
    if verify.status_code != 200 or "is_valid:true" not in verify.text:
        abort(400, "Steam login verification failed.")

    claimed_id = request.args.get("openid.claimed_id", "")
    steamid64 = steamid_from_openid_claimed_id(claimed_id)
    if not steamid64:
        abort(400, "Could not read SteamID.")

    # Ownership check for MX Bikes
    if not owns_mxb(steamid64):
        # Common issue: profile / game details private
        msg = ("❌ Link failed: could not verify MX Bikes ownership.\n"
               "Make sure your Steam **Game Details** privacy is set to **Public**, then try again.")
        discord_dm(discord_user_id, msg)
        return msg, 403

    # Save link + cleanup pending
    with sqlite3.connect(DB) as con:
        con.execute("INSERT OR REPLACE INTO linked(discord_user_id, steamid64, linked_at) VALUES(?,?,?)",
                    (discord_user_id, steamid64, int(time.time())))
        con.execute("DELETE FROM pending WHERE state=?", (state,))
        con.commit()

    # Assign Linked role in Discord
    discord_add_role(discord_user_id)
    discord_dm(discord_user_id, "✅ Steam linked and MX Bikes ownership verified. You now have access to races.")

    return "Linked ✅ You can close this tab and return to Discord."


if __name__ == "__main__":
    db_init()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
