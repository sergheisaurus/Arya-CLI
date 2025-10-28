from flask import current_app
import requests


def _headers_for(host: str, cache: dict, prefer_id=False) -> dict:
    h = {"Accept": "application/json, text/plain, */*", "User-Agent": "arya-viewer/0.1"}
    if host == current_app.config["SERVICES_HOST"] or prefer_id:
        h["authorization"] = cache["id_token"]
    else:
        h["Authorization"] = f"Bearer {cache['access_token']}"
    return h


def request(method, url, host, cache, timeout=30, **kwargs):
    headers = kwargs.pop("headers", {})
    base_headers = _headers_for(host, cache, prefer_id=(host == current_app.config["SERVICES_HOST"]))
    base_headers.update(headers)

    resp = requests.request(method, url, headers=base_headers, timeout=timeout, **kwargs)
    if resp.status_code == 401:
        # flip header style and retry once
        h2 = dict(base_headers)
        if "authorization" in h2:
            tok = h2.pop("authorization")
            h2["Authorization"] = f"Bearer {tok}"
        elif "Authorization" in h2:
            tok = h2.pop("Authorization").replace("Bearer ", "", 1)
            h2["authorization"] = tok
        resp = requests.request(method, url, headers=h2, timeout=timeout, **kwargs)
    return resp


def get_json_or_text(resp):
    ctype = resp.headers.get("content-type", "")
    if "application/json" in ctype:
        try:
            return resp.json()
        except Exception:
            return {"raw": resp.text}
    return {"raw": resp.text}

