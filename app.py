import os
import time
import hmac
import hashlib
import sqlite3
import urllib.parse
import requests
from flask import Flask, request, redirect, jsonify

app = Flask(__name__)

DB_PATH = os.getenv("DB_PATH", "championship.db")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")  # e.g. https://yourapp.onrender.com
STEAM_API_KEY = os.getenv("STEAM_API_KEY", "").strip()  # optional but recommended
LINK_SIGNING_SECRET = os.getenv("LINK_SIGNING_SECRET", "").strip()  # recommended

if not BASE_URL:
    raise RuntimeError("Missing BASE_URL env var (your web app public URL)")

STEAM_OPENID_URL = "https://steamcommunity.com/openid/login"

def db_init():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS links (
            discord_id TEXT PRIMARY KEY,
            steam_id TEXT NOT NULL,
            persona_name TEXT
        )
    """)
    con.commit()
    con.close()

def sign_discord_id(discord_id: str) -> str:
    if not LINK_SIGNING_SECRET:
        return ""
    sig = hmac.new(LINK_SIGNING_SECRET.encode("utf-8"), discord_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return sig

def verify_signature(discord_id: str, sig: str) -> bool:
    if not LINK_SIGNING_SECRET:
        # If you didn't set a secret, we can't verify. (Still works, just less secure.)
        return True
    expected = sign_discord_id(discord_id)
    return hmac.compare_digest(expected, sig or "")

def steam_openid_redirect(discord_id: str) -> str:
    # Pass discord_id + signature through return_to
    sig = sign_discord_id(discord_id)
    return_to = f"{BASE_URL}/steam/callback?discord_user_id={urllib.parse.quote(discord_id)}&sig={urllib.parse.quote(sig)}"

    params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "checkid_setup",
        "openid.return_to": return_to,
        "openid.realm": BASE_URL,
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
    }
    return f"{STEAM_OPENID_URL}?{urllib.parse.urlencode(params)}"

def validate_openid(args) -> bool:
    # Steam OpenID validation requires POST back with mode=check_authentication
    data = dict(args)
    data["openid.mode"] = "check_authentication"
    try:
        r = requests.post(STEAM_OPENID_URL, data=data, timeout=15)
        return "is_valid:true" in r.text
    except Exception:
        return False

def extract_steam_id(claimed_id: str) -> str:
    # claimed_id looks like: https://steamcommunity.com/openid/id/7656119...
    if not claimed_id:
        return ""
    parts = claimed_id.rstrip("/").split("/")
    return parts[-1] if parts else ""

def fetch_persona(steam_id: str) -> str:
    if not STEAM_API_KEY or not steam_id:
        return ""
    try:
        url = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/"
        r = requests.get(url, params={"key": STEAM_API_KEY, "steamids": steam_id}, timeout=15)
        if r.status_code != 200:
            return ""
        js = r.json()
        players = js.get("response", {}).get("players", [])
        if not players:
            return ""
        return players[0].get("personaname", "") or ""
    except Exception:
        return ""

def save_link(discord_id: str, steam_id: str, persona: str):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO links(discord_id, steam_id, persona_name)
        VALUES (?,?,?)
        ON CONFLICT(discord_id) DO UPDATE SET
          steam_id=excluded.steam_id,
          persona_name=excluded.persona_name
    """, (discord_id, steam_id, persona))
    con.commit()
    con.close()

def get_link(discord_id: str):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT steam_id, persona_name FROM links WHERE discord_id=?", (discord_id,))
    row = cur.fetchone()
    con.close()
    return row

@app.get("/")
def home():
    return "12 O’Clock Boyz Steam Link App ✅"

@app.get("/steam/start")
def steam_start():
    db_init()
    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return "Missing/invalid discord_user_id", 400
    return redirect(steam_openid_redirect(discord_user_id))

@app.get("/steam/callback")
def steam_callback():
    db_init()
    discord_user_id = request.args.get("discord_user_id", "").strip()
    sig = request.args.get("sig", "").strip()

    if not discord_user_id.isdigit():
        return "Missing/invalid discord_user_id", 400
    if not verify_signature(discord_user_id, sig):
        return "Invalid signature", 403

    # Validate OpenID response
    if not validate_openid(request.args):
        return "Steam OpenID validation failed", 403

    claimed_id = request.args.get("openid.claimed_id", "")
    steam_id = extract_steam_id(claimed_id)
    if not steam_id.isdigit():
        return "Could not extract SteamID", 400

    persona = fetch_persona(steam_id)
    save_link(discord_user_id, steam_id, persona)

    # simple success page
    return f"✅ Linked! SteamID: {steam_id} Persona: {persona}"

@app.get("/api/status")
def api_status():
    db_init()
    discord_user_id = request.args.get("discord_user_id", "").strip()
    if not discord_user_id.isdigit():
        return jsonify({"linked": False, "error": "invalid discord_user_id"}), 400

    row = get_link(discord_user_id)
    if not row:
        return jsonify({"linked": False})

    steam_id, persona = row[0], row[1]
    return jsonify({
        "linked": True,
        "steam_id": steam_id,
        "persona_name": persona
    })

if __name__ == "__main__":
    # For local dev only
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
