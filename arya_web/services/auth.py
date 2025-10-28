import json
import time
from pathlib import Path
from typing import Optional

from flask import current_app
from pycognito import Cognito


class NeedReauth(Exception):
    """Raised when refresh fails and user must re-authenticate."""
    pass


def _cache_path() -> Path:
    return current_app.config["CACHE_PATH"]


def _login_file_path() -> Path:
    return current_app.config["LOGIN_FILE_PATH"]


def load_cache():
    path = _cache_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_cache(cache):
    _cache_path().write_text(json.dumps(cache, indent=2), encoding="utf-8")


def ensure_access(cache: dict) -> dict:
    now = int(time.time())
    if now < cache.get("access_token_expires_at", 0):
        return cache

    cognito = Cognito(
        user_pool_id=cache["user_pool_id"],
        client_id=cache["client_id"],
        user_pool_region=cache["region"],
        username=cache["username"],
    )
    cognito.id_token = cache.get("id_token")
    cognito.access_token = cache.get("access_token")
    cognito.refresh_token = cache.get("refresh_token")
    try:
        cognito.renew_access_token()
    except Exception as e:
        # Refresh token invalid/expired/revoked
        try:
            _cache_path().unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        raise NeedReauth("Invalid or expired refresh token; please log in again") from e

    cache["access_token"] = cognito.access_token
    cache["id_token"] = cognito.id_token
    cache["refresh_token"] = cognito.refresh_token or cache["refresh_token"]
    cache["access_token_expires_at"] = int(time.time()) + 3300
    save_cache(cache)
    return cache


def is_authed() -> bool:
    cache = load_cache()
    return bool(cache and cache.get("access_token") and cache.get("id_token"))


def do_srp_login(username: str, password: str) -> dict:
    user = Cognito(
        user_pool_id=current_app.config["USER_POOL_ID"],
        client_id=current_app.config["CLIENT_ID"],
        user_pool_region=current_app.config["REGION"],
        username=username,
    )
    user.authenticate(password=password)
    now = int(time.time())
    return {
        "username": username,
        "region": current_app.config["REGION"],
        "user_pool_id": current_app.config["USER_POOL_ID"],
        "client_id": current_app.config["CLIENT_ID"],
        "created_at": now,
        "access_token": user.access_token,
        "id_token": user.id_token,
        "refresh_token": user.refresh_token,
        "access_token_expires_at": now + 3300,
    }


def try_login_from_file():
    path = _login_file_path()
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        email = data.get("email") or data.get("username")
        password = data.get("password")
        if not email or not password:
            return False
        cache = do_srp_login(email, password)
        save_cache(cache)
        return True
    except Exception:
        return False
