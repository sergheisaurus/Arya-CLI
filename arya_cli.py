#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
from getpass import getpass
from typing import Any, Dict, Optional
import requests
import base64
from pathlib import Path
import time, base64
from datetime import datetime, timezone

BASE = "https://arya.services.spinetix.com"
COGNITO_IDP = "https://cognito-idp.eu-central-1.amazonaws.com/"
COGNITO_CLIENT_ID = "at6lgqnsnrjtbhrl30s6knvns"

# default search order for token files (first that exists wins)
DEFAULT_TOKEN_CANDIDATES = [
    ".arya_tokens.json",
    "arya_tokens.json",
    ".arya_session.json",
    "arya_session.json",
    ".tokens.json",
    "tokens.json",
]
LOGIN_FILE = "login.json"

DEFAULT_MEDIA_PARAMS = {
    "dir": "horizontal",
    "max": 30,
    "validity": 1,
    "width": 424,
    "use_qsa": 1,
}

DEFAULT_PLAYER_MAX = 30

OUTPUT_JSON_PATH: Optional[str] = None
EXECUTION_STARTED_AT = time.time()

def extract_output_json_arg(argv, parser: argparse.ArgumentParser):
    """Extract --output-json appearing anywhere in argv; return (value, cleaned_argv)."""
    output = None
    cleaned = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--output-json":
            if i + 1 >= len(argv):
                parser.error("--output-json option requires a value")
            output = argv[i + 1]
            i += 2
            continue
        if arg.startswith("--output-json="):
            value = arg.split("=", 1)[1]
            if not value:
                parser.error("--output-json option requires a value")
            output = value
            i += 1
            continue
        cleaned.append(arg)
        i += 1
    return output, cleaned


LOGIN_FILE = "login.json"

def jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    b = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(b).decode("utf-8"))
    except Exception:
        return {}

def srp_login_into_tokens_file(token_path: str) -> Dict[str, Any]:
    # minimal SRP using pycognito (same config you used)
    from pycognito import Cognito
    with open(LOGIN_FILE, "r", encoding="utf-8") as f:
        creds = json.load(f)
    username = creds.get("email") or creds.get("username")
    password = creds["password"]
    user = Cognito(
        user_pool_id="eu-central-1_sjczhcQCX",
        client_id="at6lgqnsnrjtbhrl30s6knvns",
        user_pool_region="eu-central-1",
        username=username,
    )
    user.authenticate(password=password)
    now_ = int(time.time())
    payload = jwt_payload(user.access_token)
    device_key = payload.get("device_key")
    tokens = {
        "username": username,
        "region": "eu-central-1",
        "user_pool_id": "eu-central-1_sjczhcQCX",
        "client_id": "at6lgqnsnrjtbhrl30s6knvns",
        "created_at": now_,
        "access_token": user.access_token,
        "id_token": user.id_token,
        "refresh_token": user.refresh_token,
        "device_key": device_key,
        "access_token_expires_at": now_ + 3300,
    }
    save_tokens(token_path, tokens)
    return tokens

def current_group_id(tokens: Dict[str, Any]) -> Optional[str]:
    tok = tokens.get("id_token") or ""
    if not tok:
        return None
    payload = jwt_payload(tok)
    return payload.get("custom:group_id") or payload.get("custom:groupId") or payload.get("cust:group_id")

def ensure_selected_account(account_id: str, token_path: str, bake: bool = True) -> Dict[str, Any]:
    """Ensure the active id_token targets account_id by switching and refreshing as the web app does.
    Default behavior (bake=True):
      1) Ensure a valid id_token (refresh if expired; SRP if needed).
      2) PUT switch to account.
      3) Refresh tokens to bake the new group into id_token. If refresh not possible or fails, SRP → PUT → refresh.
    If bake=False: just PUT switch (ensure a valid id_token for the PUT), skip the final refresh.
    Returns tokens; when bake=True the id_token targets account_id.
    """
    tokens = load_tokens(token_path) or {}

    def need_valid_id() -> bool:
        return not tokens.get("id_token") or not has_valid_id_token(tokens)

    def ensure_valid_id() -> None:
        nonlocal tokens
        if need_valid_id():
            if can_refresh(tokens):
                try:
                    tokens = refresh_tokens(tokens, token_path)
                except SystemExit:
                    # Stale/invalid refresh token → fall back to SRP seamlessly
                    tokens = srp_login_into_tokens_file(token_path)
            else:
                tokens = srp_login_into_tokens_file(token_path)

    def do_switch() -> None:
        h = auth_header_id(tokens["id_token"])
        r = requests.put(f"{BASE}/v1/group/accounts/{account_id}", headers=h, data=b"")
        ensure_ok(r)

    # 1) Ensure valid id_token for the PUT
    ensure_valid_id()

    # 2) Switch
    do_switch()

    # Fast mode: skip baking
    if not bake:
        return tokens

    # 3) Refresh to bake new group
    if can_refresh(tokens):
        try:
            tokens = refresh_tokens(tokens, token_path)
            return tokens
        except SystemExit:
            # fall through to SRP below
            pass

    # SRP fallback then bake
    tokens = srp_login_into_tokens_file(token_path)
    do_switch()
    if not can_refresh(tokens):
        raise SystemExit("SRP login returned no refresh_token; cannot finalize account switch.")
    try:
        tokens = refresh_tokens(tokens, token_path)
    except SystemExit:
        # As a last resort, return SRP tokens (unbaked) to avoid throwing.
        return tokens
    return tokens

def read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def now() -> int:
    return int(time.time())

def pick_tokens_file(explicit_path: Optional[str] = None, candidates=DEFAULT_TOKEN_CANDIDATES) -> str:
    if explicit_path:
        return explicit_path
    for c in candidates:
        if os.path.exists(c):
            return c
    # fall back to default
    return DEFAULT_TOKEN_CANDIDATES[0]

def load_tokens(token_path: str) -> Dict[str, Any]:
    t = read_json(token_path) or {}
    return t

def save_tokens(token_path: str, tokens: Dict[str, Any]) -> None:
    write_json(token_path, tokens)

def emit_result(data: Any, summary: Optional[str] = None) -> None:
    wrote_file = False
    if OUTPUT_JSON_PATH:
        payload = {
            "command": " ".join(sys.argv),
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(max(0.0, time.time() - EXECUTION_STARTED_AT), 3),
            "result": data,
        }
        try:
            with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            wrote_file = True
        except Exception as exc:
            raise SystemExit(f"Failed to write JSON output to '{OUTPUT_JSON_PATH}': {exc}")
    if wrote_file:
        message = summary or f"Result written to {OUTPUT_JSON_PATH}"
        print(message)
    else:
        print(json.dumps(data, indent=2))

def _player_query_params(max_value: Optional[int], status_only: bool) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    if max_value is not None:
        params["max"] = max_value
    elif DEFAULT_PLAYER_MAX is not None:
        params["max"] = DEFAULT_PLAYER_MAX
    if status_only:
        params["statusOnly"] = 1
    return params

def _extract_players(payload: Any) -> Optional[list]:
    if isinstance(payload, dict):
        players = payload.get("players")
        return players if isinstance(players, list) else None
    if isinstance(payload, list):
        return payload
    return None

def _filter_players(players: Optional[list], serial: Optional[str]) -> list:
    if not serial:
        return list(players or [])
    serial_norm = serial.strip()
    return [
        p
        for p in (players or [])
        if isinstance(p, dict) and str(p.get("serialNumber", "")).strip() == serial_norm
    ]

def auth_header_id(id_token: str) -> Dict[str, str]:
    # Arya expects the raw JWT in `authorization`
    return {"authorization": id_token}

def ensure_ok(resp: requests.Response) -> None:
    if not resp.ok:
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        raise SystemExit(f"[{resp.status_code}] {resp.request.method} {resp.url}\n{body}")

def parse_jwt_exp(jwt_token: str) -> Optional[int]:
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        return int(payload.get("exp")) if "exp" in payload else None
    except Exception:
        return None

def has_valid_id_token(tokens: Dict[str, Any]) -> bool:
    tok = tokens.get("id_token")
    if not tok:
        return False
    exp = parse_jwt_exp(tok)
    if exp is None:
        # unknown expiry; assume valid and let server tell us if not
        return True
    # consider valid if more than ~15s left
    return now() < (exp - 15)

def can_refresh(tokens: Dict[str, Any]) -> bool:
    # Allow refresh with just refresh_token; DEVICE_KEY is optional if device tracking is disabled.
    return bool(tokens.get("refresh_token"))

def refresh_tokens(tokens: Dict[str, Any], token_path: str) -> Dict[str, Any]:
    if not can_refresh(tokens):
        # graceful: no refresh possible
        raise SystemExit(
            "Token refresh needed but refresh_token/device_key not found in your token file.\n"
            "Either log in with a flow that stores them, or re-run your working fetch/login to regenerate."
        )
    auth_params = {"REFRESH_TOKEN": tokens["refresh_token"]}
    if tokens.get("device_key"):
        auth_params["DEVICE_KEY"] = tokens["device_key"]
    headers = {
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": "AWSCognitoIdentityProviderService.InitiateAuth",
    }

    def do_refresh(flow: str) -> Optional[requests.Response]:
        pl = {
            "ClientId": COGNITO_CLIENT_ID,
            "AuthFlow": flow,
            "AuthParameters": auth_params,
        }
        resp = requests.post(COGNITO_IDP, headers=headers, json=pl)
        return resp if resp.ok else None

    # Try the flow observed in the web app first
    r = do_refresh("REFRESH_TOKEN") or do_refresh("REFRESH_TOKEN_AUTH")
    if not r:
        # Neither flow worked; get the last response for error context
        pl = {
            "ClientId": COGNITO_CLIENT_ID,
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "AuthParameters": auth_params,
        }
        r_err = requests.post(COGNITO_IDP, headers=headers, json=pl)
        ensure_ok(r_err)
        r = r_err
    data = r.json().get("AuthenticationResult", {})
    access_token = data.get("AccessToken")
    id_token = data.get("IdToken")
    expires_in = data.get("ExpiresIn", 3600)
    if not access_token or not id_token:
        raise SystemExit("Refresh succeeded but tokens missing in response.")
    tokens.update(
        {
            "access_token": access_token,
            "id_token": id_token,
            "expires_at": now() + int(expires_in) - 30,
        }
    )
    save_tokens(token_path, tokens)
    return tokens

def get_ready_tokens(token_path: str, allow_no_refresh: bool = True) -> Dict[str, Any]:
    tokens = load_tokens(token_path)
    if not tokens:
        raise SystemExit(f"No tokens found. Provide a token file or run a login flow first. (Looked at '{token_path}')")

    # if id_token still valid, use it
    if has_valid_id_token(tokens):
        return tokens

    # try refresh if possible
    if can_refresh(tokens):
        return refresh_tokens(tokens, token_path)

    # if we get here and allow_no_refresh: proceed & let 401 tell us
    if allow_no_refresh and tokens.get("id_token"):
        return tokens

    raise SystemExit("No valid id_token and refresh isn’t possible (missing refresh_token).")

# ----------------------------
# Commands
# ----------------------------
def cmd_login(args):
    token_path = pick_tokens_file(args.token_file)
    # If you already used arya_fetch, you likely have a valid id_token there.
    tokens = load_tokens(token_path)
    if not tokens:
        # optional: bootstrap via login.json (email/password) — not implemented here to avoid duplicating your working flow
        raise SystemExit(
            f"No tokens found in {token_path}. Run your working login/fetch once so tokens are saved, "
            "or tell me to embed the full password flow here."
        )
    # Try refresh if needed and possible, else just print what we have.
    if not has_valid_id_token(tokens) and can_refresh(tokens):
        tokens = refresh_tokens(tokens, token_path)

    out = {
        "access_token": tokens.get("access_token"),
        "id_token": tokens.get("id_token"),
        "refresh_token": tokens.get("refresh_token"),
        "device_key": tokens.get("device_key"),
    }
    emit_result(out)

def cmd_switch(args):
    token_path = pick_tokens_file(args.token_file)
    # Always bake (switch + refresh) to ensure id_token targets the selected account
    tokens = ensure_selected_account(args.account_id, token_path, bake=True)
    gid = current_group_id(tokens)
    headers = auth_header_id(tokens["id_token"]) if tokens.get("id_token") else {}
    gname = _lookup_group_name(headers, gid) if gid else None
    emit_result({"message": "Account selected", "group_id": gid, "group_name": gname})

def _lookup_group_name(headers: Dict[str, str], group_id: Optional[str]) -> Optional[str]:
    # 1) Try /v1/group/info (fast, current account)
    try:
        r = requests.get(f"{BASE}/v1/group/info", headers=headers)
        if r.ok:
            j = r.json()
            name = (
                j.get("name")
                or j.get("displayName")
                or j.get("title")
                or (j.get("address") or {}).get("companyName")
            )
            if name:
                return name
    except Exception:
        pass

    # 2) Try known account listing endpoints and match by id
    for u in (
        f"{BASE}/v1/group/accounts",
        f"{BASE}/v1/accounts",
        f"{BASE}/v1/group/accounts/list",
    ):
        try:
            r = requests.get(u, headers=headers)
            if not r.ok:
                continue
            data = r.json()
            arr = (
                data.get("accounts")
                if isinstance(data, dict) and "accounts" in data
                else (data if isinstance(data, list) else data.get("items", []))
            )
            for it in arr or []:
                acc_id = it.get("groupId") or it.get("id") or it.get("accountId") or it.get("gid")
                if acc_id and acc_id == group_id:
                    name = (
                        it.get("name")
                        or it.get("displayName")
                        or it.get("title")
                        or (it.get("address") or {}).get("companyName")
                    )
                    if name:
                        return name
        except Exception:
            continue

    return None

def cmd_whoami(args):
    token_path = pick_tokens_file(args.token_file)
    tokens = get_ready_tokens(token_path)
    id_token = tokens["id_token"]

    # Decode JWT payload
    parts = id_token.split(".")
    pad = "=" * ((4 - len(parts[1]) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad).decode("utf-8"))
    group_id = payload.get("custom:group_id") or payload.get("custom:groupId") or payload.get("cust:group_id")

    headers = {"authorization": id_token}
    group_name = _lookup_group_name(headers, group_id)

    out = {
        "group_id": group_id,
        "group_name": group_name,
        "aud": payload.get("aud"),
        "exp": payload.get("exp"),
        "username": payload.get("cognito:username"),
    }
    emit_result(out)

def cmd_current(args):
    token_path = pick_tokens_file(args.token_file)
    tokens = get_ready_tokens(token_path)
    h = auth_header_id(tokens["id_token"])

    info = requests.get(f"{BASE}/v1/group/info", headers=h)
    ensure_ok(info)
    me = requests.get(f"{BASE}/v1/group/users/me", headers=h)
    ensure_ok(me)
    emit_result({"group_info": info.json(), "me": me.json()})

def fetch_accounts_list(tokens: Dict[str, Any]) -> list:
    h = auth_header_id(tokens["id_token"])
    tried = []

    def try_get(u: str) -> Optional[requests.Response]:
        tried.append(u)
        r = requests.get(u, headers=h)
        return r if r.ok else None

    r = (
        try_get(f"{BASE}/v1/group/accounts")
        or try_get(f"{BASE}/v1/accounts")
        or try_get(f"{BASE}/v1/group/accounts/list")
    )
    if not r:
        raise SystemExit("Could not list accounts. Tried:\n  " + "\n  ".join(tried))

    data = r.json()
    if isinstance(data, dict) and "accounts" in data:
        arr = data.get("accounts")
    elif isinstance(data, list):
        arr = data
    elif isinstance(data, dict):
        arr = data.get("items", [])
    else:
        arr = []

    items = []
    for it in arr or []:
        acc_id = (
            it.get("groupId")
            or it.get("id")
            or it.get("accountId")
            or it.get("gid")
        )
        name = (
            it.get("name")
            or it.get("displayName")
            or it.get("title")
            or ""
        )
        if acc_id:
            items.append({"accountId": acc_id, "name": name})
    return items

def cmd_accounts(args):
    token_path = pick_tokens_file(args.token_file)
    tokens = get_ready_tokens(token_path)
    items = fetch_accounts_list(tokens)
    emit_result(items)

def cmd_media(args):
    token_path = pick_tokens_file(args.token_file)

    if args.account:
        # Ensure the id_token is bound to that account when fetching media.
        ensure_selected_account(args.account, token_path, bake=True)

    tokens = get_ready_tokens(token_path)
    h = auth_header_id(tokens["id_token"])

    params = {
        "dir": args.dir or DEFAULT_MEDIA_PARAMS["dir"],
        "max": args.max if args.max is not None else DEFAULT_MEDIA_PARAMS["max"],
        "validity": args.validity if args.validity is not None else DEFAULT_MEDIA_PARAMS["validity"],
        "width": args.width if args.width is not None else DEFAULT_MEDIA_PARAMS["width"],
        "use_qsa": 1 if args.use_qsa else DEFAULT_MEDIA_PARAMS["use_qsa"],
    }
    if args.q:
        params["q"] = args.q

    r = requests.get(f"{BASE}/v1/media", headers=h, params=params)
    ensure_ok(r)
    emit_result(r.json())

def cmd_players(args):
    token_path = pick_tokens_file(args.token_file)

    if args.account:
        ensure_selected_account(args.account, token_path, bake=True)

    tokens = get_ready_tokens(token_path)
    h = auth_header_id(tokens["id_token"])

    params = _player_query_params(args.max, args.status_only)

    r = requests.get(f"{BASE}/v1/player", headers=h, params=params)
    ensure_ok(r)
    payload = r.json()

    if args.serial:
        players = _extract_players(payload)
        payload = {"players": _filter_players(players, args.serial)}

    emit_result(payload)

def cmd_players_all(args):
    token_path = pick_tokens_file(args.token_file)
    tokens = get_ready_tokens(token_path)
    original_group = current_group_id(tokens)

    accounts = fetch_accounts_list(tokens)
    results = []
    errors = []

    params = _player_query_params(args.max, args.status_only)

    for account in accounts:
        acc_id = account.get("accountId")
        if not acc_id:
            continue
        try:
            tokens = ensure_selected_account(acc_id, token_path, bake=True)
            headers = auth_header_id(tokens["id_token"])
            resp = requests.get(f"{BASE}/v1/player", headers=headers, params=params)
            if not resp.ok:
                try:
                    err_body = resp.json()
                except Exception:
                    err_body = resp.text
                errors.append(
                    {
                        "accountId": acc_id,
                        "accountName": account.get("name"),
                        "status": resp.status_code,
                        "error": err_body,
                    }
                )
                continue
            payload = resp.json()
            players = _extract_players(payload)
            filtered_players = _filter_players(players, args.serial)
            results.append(
                {
                    "accountId": acc_id,
                    "accountName": account.get("name"),
                    "players": filtered_players,
                }
            )
        except SystemExit:
            raise
        except Exception as exc:
            errors.append(
                {
                    "accountId": acc_id,
                    "accountName": account.get("name"),
                    "error": str(exc),
                }
            )

    if original_group:
        try:
            ensure_selected_account(original_group, token_path, bake=True)
        except SystemExit:
            pass
        except Exception:
            pass

    summary = None
    if OUTPUT_JSON_PATH:
        total_players = sum(len(acc.get("players", [])) for acc in results)
        summary = (
            f"Wrote players for {len(results)} accounts "
            f"({total_players} players, {len(errors)} errors) to {OUTPUT_JSON_PATH}"
        )
    emit_result({"accounts": results, "errors": errors}, summary=summary)
def cmd_mediaget(args):
    token_path = pick_tokens_file(args.token_file)
    tokens = get_ready_tokens(token_path)
    h = auth_header_id(tokens["id_token"])
    params = {"use_qsa": 1} if args.use_qsa else {}
    r = requests.get(f"{BASE}/v1/media/{args.resource_id}", headers=h, params=params)
    ensure_ok(r)
    emit_result(r.json())

def main():
    ap = argparse.ArgumentParser(prog="arya_cli", description="Arya CLI")
    ap.add_argument("--token-file", help="Path to token file (default: auto-detect among common names)")
    ap.add_argument(
        "--output-json",
        help="Write command output (with metadata) to this JSON file",
    )

    sub = ap.add_subparsers(dest="cmd")

    # login / whoami / current / accounts
    sp_login = sub.add_parser("login", help="Show/refresh tokens using existing token file")
    sp_login.set_defaults(func=cmd_login)

    sp_switch = sub.add_parser("switch", help="Switch active account (does PUT + refresh like the web app)")
    sp_switch.add_argument("account_id")
    sp_switch.set_defaults(func=cmd_switch)

    sp_whoami = sub.add_parser("whoami", help="Show which account/group the current id_token targets")
    sp_whoami.set_defaults(func=cmd_whoami)

    sp_current = sub.add_parser("current", help="Show current group info and user")
    sp_current.set_defaults(func=cmd_current)

    sp_accounts = sub.add_parser("accounts", help="List accounts you can switch to")
    sp_accounts.set_defaults(func=cmd_accounts)

    # MEDIA — define ONCE with all args (including --account)
    sp_media = sub.add_parser("media", help="List media with defaults")
    sp_media.add_argument("--account", help="Optional: switch to this account first (does PUT + refresh)")
    sp_media.add_argument("--dir", default=DEFAULT_MEDIA_PARAMS["dir"])
    sp_media.add_argument("--max", type=int, default=DEFAULT_MEDIA_PARAMS["max"])
    sp_media.add_argument("--validity", type=int, default=DEFAULT_MEDIA_PARAMS["validity"])
    sp_media.add_argument("--width", type=int, default=DEFAULT_MEDIA_PARAMS["width"])
    sp_media.add_argument("--use-qsa", dest="use_qsa", action="store_true", default=True)
    sp_media.add_argument("-q", help="search query")
    sp_media.set_defaults(func=cmd_media)

    sp_players = sub.add_parser("players", help="List players for the current account")
    sp_players.add_argument("--account", help="Optional: switch to this account first (does PUT + refresh)")
    sp_players.add_argument(
        "--max",
        type=int,
        default=DEFAULT_PLAYER_MAX,
        help="Maximum number of players to return (default: %(default)s)",
    )
    sp_players.add_argument(
        "--status-only",
        action="store_true",
        help="Request compact status info (sets statusOnly=1 on the API call)",
    )
    sp_players.add_argument(
        "--serial",
        help="Filter the returned list to a specific serial number (client-side filter)",
    )
    sp_players.set_defaults(func=cmd_players)

    sp_players_all = sub.add_parser("players-all", help="List players for every accessible account")
    sp_players_all.add_argument(
        "--max",
        type=int,
        default=DEFAULT_PLAYER_MAX,
        help="Maximum number of players to request per account (default: %(default)s)",
    )
    sp_players_all.add_argument(
        "--status-only",
        action="store_true",
        help="Request compact status info for each account (sets statusOnly=1)",
    )
    sp_players_all.add_argument(
        "--serial",
        help="Filter players by serial number across all accounts (client-side filter)",
    )
    sp_players_all.set_defaults(func=cmd_players_all)

    # mediaget
    sp_mget = sub.add_parser("mediaget", help="Get a single media object")
    sp_mget.add_argument("resource_id")
    sp_mget.add_argument("--no-qsa", dest="use_qsa", action="store_false", default=True)
    sp_mget.set_defaults(func=cmd_mediaget)

    argv = sys.argv[1:]
    extracted_output, argv = extract_output_json_arg(argv, ap)
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        sys.exit(0)
    global OUTPUT_JSON_PATH
    OUTPUT_JSON_PATH = extracted_output if extracted_output is not None else args.output_json
    if OUTPUT_JSON_PATH is not None:
        setattr(args, "output_json", OUTPUT_JSON_PATH)
    args.func(args)

if __name__ == "__main__":
    main()
