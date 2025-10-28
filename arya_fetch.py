#!/usr/bin/env python3
"""
ARYA interactive client — auto host + token type + quick defaults + MEDIA.

Shortcuts:
  DEFAULTS → ME, INFO, STORAGE, USERDB, ACCOUNTS
  ME       → /v1/group/users/me
  INFO     → /v1/group/info
  STORAGE  → /v1/group/storage
  USERDB   → /v1/userdb/
  ACCOUNTS → tries common accounts endpoints
  MEDIA    → /v1/media with handy params (dir/max/validity/width/use_qsa/q)

Examples:
  MEDIA
  MEDIA dir=vertical max=50 width=640
  MEDIA q=logo  validity=1
  GET /v1/media?dir=horizontal&max=10   (raw still works)
"""

import json
import time
import sys
from pathlib import Path
from urllib.parse import urlencode

import requests
from pycognito import Cognito
import sys

# --- Hosts ---
CLOUD_HOST = "https://arya.spinetix.cloud"
SERVICES_HOST = "https://arya.services.spinetix.com"

CACHE_PATH = Path(".arya_tokens.json")
SHOW_HEADERS = False


def load_cache():
    if not CACHE_PATH.exists():
        sys.exit("No token cache found. Run `python arya_login.py` first.")
    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cache(cache):
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def ensure_access_token(cache):
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
        # Most likely: NotAuthorizedException Invalid Refresh Token
        print("\nERROR: Refresh failed (invalid/expired refresh token).", file=sys.stderr)
        print("Run: python arya_login.py  (or update login.json and retry)", file=sys.stderr)
        sys.exit(1)

    cache["access_token"] = cognito.access_token
    cache["id_token"] = cognito.id_token
    cache["refresh_token"] = cognito.refresh_token or cache["refresh_token"]
    cache["access_token_expires_at"] = int(time.time()) + 3300
    save_cache(cache)
    return cache


def _build_headers(cache, host, prefer_id_token=False):
    """
    For SERVICES_HOST endpoints (/v1/...), ARYA expects:
        authorization: <ID_TOKEN>    (no 'Bearer')
    For CLOUD_HOST endpoints, use:
        Authorization: Bearer <ACCESS_TOKEN>
    """
    headers = {"Accept": "application/json, text/plain, */*", "User-Agent": "arya-fetch/1.3"}
    if host == SERVICES_HOST or prefer_id_token:
        headers["authorization"] = cache["id_token"]
    else:
        headers["Authorization"] = f"Bearer {cache['access_token']}"
    return headers


def _request_with_auto_flip(method, url, headers, json_body=None, data=None):
    """Send request; on 401, flip token style and retry once."""
    resp = requests.request(method, url, headers=headers, json=json_body, data=data, timeout=30)
    if resp.status_code == 401:
        h = dict(headers)
        if "authorization" in h:
            tok = h.pop("authorization")
            h["Authorization"] = f"Bearer {tok}"
        elif "Authorization" in h:
            tok = h.pop("Authorization").replace("Bearer ", "", 1)
            h["authorization"] = tok
        resp = requests.request(method, url, headers=h, json=json_body, data=data, timeout=30)
    return resp


def do_request(method, path, body=None):
    cache = ensure_access_token(load_cache())

    # pick host & default header style by path
    if path.startswith("/v1/"):
        base = SERVICES_HOST
        prefer_id = True
    else:
        base = CLOUD_HOST
        prefer_id = False

    url = path if path.startswith("http") else f"{base}{path}"

    # body
    json_body, data = None, None
    if body:
        try:
            json_body = json.loads(body)
        except Exception:
            data = body

    headers = _build_headers(cache, base, prefer_id_token=prefer_id)
    resp = _request_with_auto_flip(method, url, headers, json_body=json_body, data=data)

    print(f"\n{method} {url} → {resp.status_code}")
    if SHOW_HEADERS:
        print("---- response headers ----")
        for k, v in resp.headers.items():
            print(f"{k}: {v}")
        print("--------------------------")

    ctype = resp.headers.get("content-type", "")
    if "application/json" in ctype:
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text[:2000])
    else:
        print(resp.text[:2000])
    print()
    return resp.status_code


# --------- Shortcuts ----------

def do_me():
    return do_request("GET", "/v1/group/users/me")

def do_info():
    return do_request("GET", "/v1/group/info")

def do_storage():
    return do_request("GET", "/v1/group/storage")

def do_userdb():
    return do_request("GET", "/v1/userdb/")

def do_accounts():
    """
    Try likely accounts endpoints in order; stop at first 200.
    """
    candidates = [
        (SERVICES_HOST, "/v1/accounts"),
        (SERVICES_HOST, "/v1/group/accounts"),
        (CLOUD_HOST,    "/accounts"),
        (CLOUD_HOST,    "/api/accounts"),
    ]
    cache = ensure_access_token(load_cache())
    for host, path in candidates:
        url = f"{host}{path}"
        headers = _build_headers(cache, host, prefer_id_token=(host == SERVICES_HOST))
        resp = _request_with_auto_flip("GET", url, headers)
        if resp.status_code == 200:
            print(f"\nGET {url} → 200 (ACCOUNTS)")
            ctype = resp.headers.get("content-type", "")
            if "application/json" in ctype:
                try:
                    print(json.dumps(resp.json(), indent=2))
                except Exception:
                    print(resp.text[:2000])
            else:
                print(resp.text[:2000])
            print()
            return 200
    print("\nACCOUNTS: none of the candidate endpoints returned 200.\n")
    return 0


def parse_kv_args(arg_str: str) -> dict:
    """
    Parse 'k=v a=b' into dict. Quotes not supported (keep simple for REPL).
    """
    params = {}
    for token in arg_str.split():
        if "=" in token:
            k, v = token.split("=", 1)
            params[k.strip()] = v.strip()
    return params


def do_media(arg_str: str | None = None):
    """
    MEDIA [dir=horizontal max=30 validity=1 width=424 use_qsa=1 q=...]
    Defaults mirror your working curl.
    """
    defaults = {
        "dir": "horizontal",
        "max": "30",
        "validity": "1",
        "width": "424",
        "use_qsa": "1",
        # optional: "q": "searchTerm"
    }
    overrides = parse_kv_args(arg_str or "")
    params = {**defaults, **overrides}

    qs = urlencode(params, doseq=True)
    path = f"/v1/media?{qs}"

    return do_request("GET", path)


def run_defaults():
    print("\n— DEFAULTS —\n")
    do_me()
    do_info()
    do_storage()
    do_userdb()
    do_accounts()


def repl():
    global SHOW_HEADERS
    print("ARYA fetcher — defaults & shortcuts (type HELP)")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye.")
            break
        if not line:
            continue

        u = line.upper()
        if u in ("QUIT", "EXIT"):
            print("bye.")
            break
        if u == "HELP":
            print("Commands:")
            print("  DEFAULTS                  → ME, INFO, STORAGE, USERDB, ACCOUNTS")
            print("  ME                        → /v1/group/users/me")
            print("  INFO                      → /v1/group/info")
            print("  STORAGE                   → /v1/group/storage")
            print("  USERDB                    → /v1/userdb/")
            print("  ACCOUNTS                  → tries common endpoints")
            print("  MEDIA [k=v ...]           → /v1/media (dir/max/validity/width/use_qsa/q)")
            print("  HEADERS                   → toggle response header printing")
            print("  GET /path [json]          → raw request (also POST/PUT/PATCH/DELETE/HEAD/OPTIONS)")
            print("  QUIT")
            continue

        if u == "HEADERS":
            SHOW_HEADERS = not SHOW_HEADERS
            print(f"Headers printing: {'ON' if SHOW_HEADERS else 'OFF'}")
            continue
        if u == "DEFAULTS":
            run_defaults(); continue
        if u == "ME":
            do_me(); continue
        if u == "INFO":
            do_info(); continue
        if u == "STORAGE":
            do_storage(); continue
        if u == "USERDB":
            do_userdb(); continue
        if u == "ACCOUNTS":
            do_accounts(); continue
        if line.upper().startswith("MEDIA"):
            args = line[len("MEDIA"):].strip()
            do_media(args); continue

        # raw method path [body]
        parts = line.split(None, 2)
        if len(parts) < 2:
            print("Format: METHOD /path [json_body]")
            continue
        method = parts[0].upper()
        path = parts[1]
        body = parts[2] if len(parts) == 3 else None
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            print("Unsupported method.")
            continue
        do_request(method, path, body)


if __name__ == "__main__":
    repl()
