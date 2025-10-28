#!/usr/bin/env python3
"""
ARYA Cognito login via SRP with optional login.json file.

Usage examples:
  # Prefer login.json if present, else fall back to prompt
  python arya_login.py

  # Force reading a specific file
  python arya_login.py --file login.json

  # Force interactive prompt (ignore any file)
  python arya_login.py --prompt

Creates/updates: ./.arya_tokens.json
"""

import argparse
import getpass
import json
import os
import time
from pathlib import Path
import base64, json

from pycognito import Cognito

# ---- ARYA Cognito config (from discovery) ----
USER_POOL_ID = "eu-central-1_sjczhcQCX"
CLIENT_ID    = "at6lgqnsnrjtbhrl30s6knvns"
REGION       = "eu-central-1"

CACHE_PATH = Path(".arya_tokens.json")
DEFAULT_LOGIN_FILE = Path("login.json")


def jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    b = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(b).decode("utf-8"))
    except Exception:
        return {}


def load_login_from_file(path: Path) -> dict | None:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise SystemExit(f"Invalid JSON in {path}: {e}")
    # Accept both 'email' and 'username' keys; 'password' is required.
    email = data.get("email") or data.get("username")
    password = data.get("password")
    if not email or not password:
        raise SystemExit(f"{path} must contain 'email' (or 'username') and 'password' fields.")
    return {"email": email, "password": password}


def prompt_login() -> dict:
    email = input("Username (email): ").strip()
    if not email:
        raise SystemExit("Username required.")
    password = getpass.getpass("Password: ")
    if not password:
        raise SystemExit("Password required.")
    return {"email": email, "password": password}


def save_cache(tokens: dict) -> None:
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    print(f"Saved tokens to {CACHE_PATH.resolve()}")
    print("Authorization header:\n  Authorization: Bearer <access_token>")
    print("\nDo NOT commit this file. Treat it as sensitive.")


def srp_login(username: str, password: str) -> dict:
    user = Cognito(
        user_pool_id=USER_POOL_ID,
        client_id=CLIENT_ID,
        user_pool_region=REGION,
        username=username,
    )
    user.authenticate(password=password)

    now = int(time.time())
    payload = jwt_payload(user.access_token)
    device_key = payload.get("device_key")  # <-- the magic

    return {
        "username": username,
        "region": REGION,
        "user_pool_id": USER_POOL_ID,
        "client_id": CLIENT_ID,
        "created_at": now,
        "access_token": user.access_token,
        "id_token": user.id_token,
        "refresh_token": user.refresh_token,
        "device_key": device_key,                 # <-- store it
        "access_token_expires_at": now + 3300,
    }


def main():
    parser = argparse.ArgumentParser(description="ARYA Cognito login with optional login.json")
    parser.add_argument("--file", "-f", type=Path, help="Path to login.json with {email,password}")
    parser.add_argument("--prompt", action="store_true", help="Force interactive prompt for credentials")
    args = parser.parse_args()

    creds = None
    if args.prompt:
        creds = prompt_login()
    else:
        file_path = args.file or DEFAULT_LOGIN_FILE
        creds = load_login_from_file(file_path) if file_path.exists() else None
        if creds is None:
            print("(No login.json found — falling back to prompt.)")
            creds = prompt_login()

    tokens = srp_login(creds["email"], creds["password"])
    save_cache(tokens)


if __name__ == "__main__":
    main()
