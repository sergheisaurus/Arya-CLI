from urllib.parse import urlencode

from flask import Blueprint, Response, current_app, flash, redirect, render_template, request, url_for
from urllib.parse import urlparse

from ..services import auth as auth_svc
from ..services.auth import NeedReauth
from ..services import http_client as http

bp = Blueprint("main", __name__)


@bp.app_context_processor
def inject_globals():
    cache = auth_svc.load_cache()
    def proxy(u: str) -> str:
        return url_for("main.preview", u=u)
    return {"authed": auth_svc.is_authed(), "cache": cache, "proxy": proxy}


@bp.route("/")
def index():
    return render_template("base.html", page="home")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("main.login"))
        try:
            cache = auth_svc.do_srp_login(email, password)
            auth_svc.save_cache(cache)
            flash("Login successful.", "ok")
            return redirect(url_for("main.dashboard"))
        except Exception as e:
            flash(f"Login failed: {e}", "error")
            return redirect(url_for("main.login"))
    # try login.json if present
    if auth_svc.try_login_from_file():
        flash("Logged in via login.json", "ok")
        return redirect(url_for("main.dashboard"))
    return render_template("login.html")


@bp.route("/logout")
def logout():
    p = current_app.config["CACHE_PATH"]
    if p.exists():
        p.unlink()
    flash("Logged out (local cache removed).", "ok")
    return redirect(url_for("main.index"))


@bp.route("/dashboard")
def dashboard():
    if not auth_svc.is_authed():
        return redirect(url_for("main.login"))
    try:
        cache = auth_svc.ensure_access(auth_svc.load_cache())
    except NeedReauth:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("main.login"))

    services = current_app.config["SERVICES_HOST"]

    r_me = http.request("GET", f"{services}/v1/group/users/me", services, cache)
    me = http.get_json_or_text(r_me)

    r_info = http.request("GET", f"{services}/v1/group/info", services, cache)
    info = http.get_json_or_text(r_info)

    r_sto = http.request("GET", f"{services}/v1/group/storage", services, cache)
    storage = http.get_json_or_text(r_sto)

    return render_template("dashboard.html", me=me, info=info, storage=storage)


@bp.route("/accounts")
def accounts():
    if not auth_svc.is_authed():
        return redirect(url_for("main.login"))
    try:
        cache = auth_svc.ensure_access(auth_svc.load_cache())
    except NeedReauth:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("main.login"))

    cloud = current_app.config["CLOUD_HOST"]
    services = current_app.config["SERVICES_HOST"]

    candidates = [
        f"{services}/v1/accounts",
        f"{services}/v1/group/accounts",
        f"{cloud}/accounts",
        f"{cloud}/api/accounts",
    ]
    best = None
    for url in candidates:
        host = services if url.startswith(services) else cloud
        resp = http.request("GET", url, host, cache)
        if resp.status_code == 200:
            best = http.get_json_or_text(resp)
            break
    return render_template("accounts.html", data=best, tried=candidates)


@bp.route("/media")
def media_list():
    if not auth_svc.is_authed():
        return redirect(url_for("main.login"))
    try:
        cache = auth_svc.ensure_access(auth_svc.load_cache())
    except NeedReauth:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("main.login"))

    services = current_app.config["SERVICES_HOST"]

    params = {
        "dir": request.args.get("dir", "horizontal"),
        "max": request.args.get("max", "30"),
        "validity": request.args.get("validity", "1"),
        "width": request.args.get("width", "424"),
        "use_qsa": request.args.get("use_qsa", "1"),
    }
    q = request.args.get("q")
    if q:
        params["q"] = q
    # pagination support
    next_token_in = request.args.get("nextToken")
    if next_token_in:
        params["nextToken"] = next_token_in

    url = f"{services}/v1/media?{urlencode(params)}"
    r = http.request("GET", url, services, cache)
    data = http.get_json_or_text(r)

    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("items", "data", "results", "media"):
            if isinstance(data.get(key), list):
                items = data[key]
                break
    next_token = data.get("nextToken") if isinstance(data, dict) else None
    next_qs = None
    if next_token:
        # Build querystring for next page based on current params (excluding any incoming nextToken)
        base_params = {k: v for k, v in params.items() if k != "nextToken"}
        base_params["nextToken"] = next_token
        next_qs = urlencode(base_params)

    return render_template("media_list.html", params=params, items=items, raw=data, next_token=next_token, next_qs=next_qs)


@bp.route("/media/<rid>")
def media_detail(rid):
    if not auth_svc.is_authed():
        return redirect(url_for("main.login"))
    cache = auth_svc.ensure_access(auth_svc.load_cache())

    services = current_app.config["SERVICES_HOST"]
    url = f"{services}/v1/media/{rid}?use_qsa=1"
    r = http.request("GET", url, services, cache)
    data = http.get_json_or_text(r)

    preview_url = None
    if isinstance(data, dict):
        preview = data.get("preview") or {}
        preview_url = preview.get("url")

    # use local proxy to improve reliability of previews
    proxied = url_for("main.preview", u=preview_url) if preview_url else None
    return render_template("media_detail.html", rid=rid, media=data, preview_url=proxied, preview_raw=preview_url)


@bp.route("/preview")
def preview():
    """Proxy remote preview URLs to avoid header/token/CORS pitfalls.
    Accepts `u` query param (absolute URL).
    """
    raw_url = request.args.get("u", type=str)
    if not raw_url:
        return Response("Missing 'u'", status=400)
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        return Response("Invalid scheme", status=400)

    # Try to attach appropriate headers only for ARYA services host
    services_base = current_app.config["SERVICES_HOST"]
    services_netloc = urlparse(services_base).netloc

    try:
        cache = auth_svc.ensure_access(auth_svc.load_cache()) if auth_svc.is_authed() else None
    except NeedReauth:
        cache = None

    import requests as _rq
    if parsed.netloc == services_netloc:
        # First try without headers to allow signed token URLs
        resp = _rq.get(raw_url, timeout=30)
        if resp.status_code in (401, 403) and cache:
            # Then try with ID token header using our helper (with 401 flip retry)
            resp = http.request("GET", raw_url, services_base, cache, timeout=30)
    else:
        resp = _rq.get(raw_url, timeout=30)

    ct = resp.headers.get("content-type", "application/octet-stream")
    return Response(resp.content, status=resp.status_code, content_type=ct)
