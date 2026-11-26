"""UI tests: builds the database with the real sgb_sync (fake API) and runs the UI as a live server."""
import datetime as dt
import json
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sync"))
import sgb_sync as sync  # noqa: E402
import sgb_ui as ui  # noqa: E402

NOW = dt.datetime.now()


def rec(i, url, days=1, desc="PH", crit=4):
    return {"id": i, "url": url, "type": "domain", "desc": desc, "source": "IH", "criticality_level": crit,
            "connectiontype": "PH", "date": (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S.1")}


RECORDS = [rec(10, "2a00:41f::36f", 1), rec(9, "garanti-kredi.cloud", 1), rec(8, "http://evil.com/login", 2), rec(7, "1.2.3.4", 3, "MC", 10),
           rec(6, "evil.com", 5), rec(5, "google.com", 6), rec(4, "garanti-firsat.cloud", 400),
           rec(3, "evil.com", 900), rec(2, "<script>alert(1)</script>.com", 1), rec(1, "old.com", 2000)]


class Resp:
    status_code = 200

    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class API:
    def mount(self, *a):
        pass

    def get(self, url, params, timeout):
        p, n = params["page"], params["per-page"]
        return Resp({"models": RECORDS[(p - 1) * n:p * n], "pageCount": 1})


@pytest.fixture
def server(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    allow = tmp_path / "allowlist.txt"
    allow.write_text("google.com\n")
    for mod in (sync, ui):
        monkeypatch.setattr(mod, "ALLOWLIST_FILE", str(allow))
    for name, rel in (("BASE_DIR", ""), ("DB_FILE", "sgb.db"), ("FEED_DIR", "feeds"), ("STATUS_FILE", "status.json"),
                      ("LOG_FILE", "sgb_sync.log"), ("RUN_MARKER", "sgb_sync.running")):
        monkeypatch.setattr(sync, name, str(data / rel) if rel else str(data))
    for name, rel in (("DB_FILE", "sgb.db"), ("FEED_DIR", "feeds"), ("STATUS_FILE", "status.json"),
                      ("SYNC_LOG", "sgb_sync.log"), ("RUN_MARKER", "sgb_sync.running")):
        monkeypatch.setattr(ui, name, str(data / rel))
    control = tmp_path / "control"
    for mod in (sync, ui):
        for name, rel in (("CONTROL_DIR", ""), ("REQUEST_FILE", "request.json"), ("STATE_FILE", "state.json")):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name, str(control / rel) if rel else str(control))
    monkeypatch.setattr(sync, "_state", {"loop": True, "last_run_started": None, "last_full_started": None})
    monkeypatch.setattr(sync, "FEED_WINDOWS", [46, 365])
    monkeypatch.setattr(sync, "make_session", lambda: API())
    monkeypatch.setattr(sync.time, "sleep", lambda s: None)
    assert sync.main() == 0
    import logging
    logging.root.handlers.clear()  # drop sync's log redirection in the same process (in reality they are separate containers)

    monkeypatch.setattr(ui, "UI_PASS", "Şifre-123")
    srv = ui.make_server("127.0.0.1", 0, ["127.0.0.1/32"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def get(path, auth=("admin", "Şifre-123")):
        req = urllib.request.Request(base + path)
        if auth:
            import base64
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode()

    def raw(path, cookie=None):
        """GET with an optional Cookie header; returns (status, headers, body)."""
        import base64
        req = urllib.request.Request(base + path)
        req.add_header("Authorization", "Basic " + base64.b64encode("admin:Şifre-123".encode()).decode())
        if cookie:
            req.add_header("Cookie", cookie)
        with urllib.request.urlopen(req) as r:
            return r.status, r.headers, r.read().decode()

    get.base = base
    get.raw = raw
    snapshot = {p: p.read_bytes() for p in data.rglob("*") if p.is_file()}
    yield get, data, snapshot
    srv.shutdown()
    srv.server_close()


def q(get, value):
    return get("/?q=" + urllib.request.quote(value, safe=""))[1]


def test_auth(server):
    get, _, _ = server
    assert get("/", auth=None)[0] == 401
    assert get("/", auth=("admin", "yanlis"))[0] == 401
    assert get("/")[0] == 200


def test_blocked_domain_with_feeds_and_history(server):
    get, _, _ = server
    body = q(get, "evil.com")
    assert "ENGELLİ" in body and "domain-part1.txt" in body and "domain-46d.txt" in body
    assert "kayıt sayısı: 2" in body                      # two separate source records (id 3 and 6)
    assert "SGB ID" not in body                           # internal API IDs are not shown to analysts
    assert "Bu host altındaki URL" in body and "evil.com/login" in body


def test_url_query_shows_url_and_host(server):
    get, _, _ = server
    body = q(get, "https://evil.com/login?x=1")
    assert "url-part1.txt" in body and "URL&#x27;nin host&#x27;u" in body


def test_old_record_only_in_full_feed(server):
    get, _, _ = server
    body = q(get, "garanti-firsat.cloud")               # 400 days ago: in the full list, not in the Lite ones
    assert "domain-part1.txt" in body and "46d" not in body.split("Firewall'a giden feed'ler")[1].split("<br>")[0]


def test_allowlisted(server):
    get, _, _ = server
    body = q(get, "google.com")
    assert "SGB listesinde var, allowlist'te" in body and "<b>google.com</b> allowlist kaydı" in body


def test_not_in_sgb(server):
    get, _, _ = server
    assert "SGB kayıtlarında yok" in q(get, "8.8.8.8")


def test_ip_with_metadata(server):
    get, _, _ = server
    body = q(get, "1.2.3.4")
    assert "ip-part1.txt" in body and "<td>MC</td>" in body and "<td>10</td>" in body


def test_keyword_search(server):
    get, _, _ = server
    body = q(get, "garanti")
    assert "Kelime araması" in body and "garanti-kredi.cloud" in body and "garanti-firsat.cloud" in body


def test_xss_escaped(server):
    get, _, _ = server
    body = q(get, "<script>alert(2)</script>")
    assert "<script>" not in body and "&lt;script&gt;" in body


def test_status_json(server):
    get, _, _ = server
    st = json.loads(get("/api/status")[1])
    assert st["ok"] and st["feed_counts"]["domain"] >= 3 and st["sgb_records"] == 9


def test_read_only(server):
    get, data, snapshot = server
    for path in ("/", "/?q=evil.com", "/?q=garanti", "/api/status"):
        get(path)
    assert {p: p.read_bytes() for p in data.rglob("*") if p.is_file()} == snapshot


def test_bare_ipv6_query(server):
    get, _, _ = server
    for query in ("2a00:41f::36f", "[2a00:41f::36f]", "http://[2a00:41f::36f]/"):
        body = q(get, query)
        assert "ENGELLİ" in body and "ipv6-part1.txt" in body, query


def test_skipped_pages_shown(server):
    get, data, _ = server
    status = json.loads((data / "status.json").read_text())
    status["skipped_pages"] = [212]
    (data / "status.json").write_text(json.dumps(status))
    body = get("/")[1]
    assert "son tam taramada 1 sayfa atlandı" in body
    assert "Son tam taramada 1 sayfa atlandı: Sayfa 212." in body
    assert "badge warn" in body
    assert json.loads(get("/api/status")[1])["skipped_pages"] == [212]


# --- Scan buttons: POST /action ---

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def post(server_get, data, form, headers=None, auth=("admin", "Şifre-123")):
    """POST to /action on the same live server; returns (status, flash code from Set-Cookie, body).
    A redirect must always go to "/" (the result is never put into the URL)."""
    import base64
    body = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(server_get.base + "/action", data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
    for k, v in (headers if headers is not None else {"Sec-Fetch-Site": "same-origin"}).items():
        req.add_header(k, v)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req) as r:
            return r.status, _flash(r.headers), r.read().decode()
    except urllib.error.HTTPError as err:
        if err.code == 303:
            assert err.headers.get("Location") == "/"
        return err.code, _flash(err.headers), err.read().decode()


def _flash(headers):
    cookie = headers.get("Set-Cookie") or ""
    if not cookie.startswith("sgb_flash="):
        return None
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Max-Age=60" in cookie
    return cookie.split(";")[0].split("=", 1)[1]


def set_state(**fields):
    state = json.loads(open(ui.STATE_FILE, encoding="utf-8").read())
    state.update(fields)
    with open(ui.STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)


def open_cooldowns():
    past = (dt.datetime.now() - dt.timedelta(minutes=1)).isoformat(timespec="seconds")
    set_state(next_full_allowed=past, next_update_allowed=past)


def test_buttons_in_header_with_token(server):
    get, _, _ = server
    body = get("/")[1]
    header = body[body.index("<header>"):body.index("</header>")]
    assert "Şimdi güncelle" in header and "Tam taramayı başlat" in header
    assert f"name='token' value='{ui.CSRF_TOKEN}'" in header and "method='post' action='/action'" in header
    assert "Sistem güncel." in header


def test_buttons_disabled_during_cooldown(server):
    get, _, _ = server                                                 # the fixture's full scan just started
    header = get("/")[1].split("</header>")[0]
    assert header.count(" disabled ") == 2
    note = header.split("class='hnote'>")[1].split("</span>")[0]
    assert "Güncelleme saat " in note and "Tam tarama saat " in note and "sonrasında istenebilir." in note


def test_full_request_is_queued(server):
    get, data, _ = server
    open_cooldowns()
    status, flash, _ = post(get, data, {"token": ui.CSRF_TOKEN, "action": "full"})
    assert status == 303 and flash == "queued_full"
    req = json.loads(open(ui.REQUEST_FILE, encoding="utf-8").read())
    assert req["mode"] == "full" and req["by"] == "admin" and req["ip"] == "127.0.0.1"
    assert "Tam tarama istendi" in get.raw("/", f"sgb_flash={flash}")[2]
    # a second request while one is waiting is not accepted
    status, flash, _ = post(get, data, {"token": ui.CSRF_TOKEN, "action": "update"})
    assert flash == "busy"
    assert json.loads(open(ui.REQUEST_FILE, encoding="utf-8").read())["mode"] == "full"


def test_update_request_is_queued(server):
    get, data, _ = server
    open_cooldowns()
    assert post(get, data, {"token": ui.CSRF_TOKEN, "action": "update"})[1] == "queued_update"
    assert json.loads(open(ui.REQUEST_FILE, encoding="utf-8").read())["mode"] == "incremental"


def test_request_refused_during_cooldown(server):
    get, data, _ = server
    assert post(get, data, {"token": ui.CSRF_TOKEN, "action": "full"})[1] == "cooldown"
    assert not os.path.exists(ui.REQUEST_FILE)


def test_request_refused_while_running_or_not_in_loop(server):
    get, data, _ = server
    open_cooldowns()
    (data / "sgb_sync.running").write_text("2026-11-26 13:02:00")
    assert post(get, data, {"token": ui.CSRF_TOKEN, "action": "full"})[1] == "busy"
    (data / "sgb_sync.running").unlink()
    set_state(loop=False)
    assert post(get, data, {"token": ui.CSRF_TOKEN, "action": "full"})[1] == "unavailable"
    assert "Senkronizasyon döngü modunda değil." in get("/")[1]
    assert not os.path.exists(ui.REQUEST_FILE)


@pytest.mark.parametrize("form,headers", [
    ({"action": "full"}, None),                                                   # no token
    ({"token": "wrong", "action": "full"}, None),                                 # wrong token
    ({"action": "full", "token": "TOKEN"}, {"Sec-Fetch-Site": "cross-site"}),     # another site
    ({"action": "full", "token": "TOKEN"}, {"Sec-Fetch-Site": "same-site"}),      # sibling site
    ({"action": "full", "token": "TOKEN"}, {}),                                   # no Fetch Metadata, no Origin
    ({"action": "full", "token": "TOKEN"}, {"Origin": "https://evil.example"}),   # foreign Origin
])
def test_forged_requests_are_rejected(server, form, headers):
    get, data, _ = server
    open_cooldowns()
    form = {k: (ui.CSRF_TOKEN if v == "TOKEN" else v) for k, v in form.items()}
    assert post(get, data, form, headers)[0] == 403
    assert not os.path.exists(ui.REQUEST_FILE)


def test_origin_fallback_without_fetch_metadata(server):
    get, data, _ = server
    open_cooldowns()
    status, flash, _ = post(get, data, {"token": ui.CSRF_TOKEN, "action": "full"}, {"Origin": get.base})
    assert status == 303 and flash == "queued_full"


def test_post_needs_password_and_valid_shape(server):
    get, data, _ = server
    open_cooldowns()
    assert post(get, data, {"token": ui.CSRF_TOKEN, "action": "full"}, auth=None)[0] == 401
    assert post(get, data, {"token": ui.CSRF_TOKEN, "action": "delete"})[0] == 400
    assert post(get, data, {"token": ui.CSRF_TOKEN, "action": "full", "pad": "x" * 2000})[0] == 413
    assert get("/action")[0] == 405
    assert not os.path.exists(ui.REQUEST_FILE)


def test_message_is_shown_once_and_not_from_the_url(server):
    get, _, _ = server
    status, headers, body = get.raw("/", "sgb_flash=queued_update")
    assert "Güncelleme istendi" in body
    clear = headers.get("Set-Cookie")
    assert clear.startswith("sgb_flash=;") and "Max-Age=0" in clear       # deleted after one view
    assert "Güncelleme istendi" not in get("/")[1]                       # reload: no cookie, no message
    assert "Güncelleme istendi" not in get("/?msg=queued_update")[1]    # the URL cannot select a message
    body = get.raw("/", "sgb_flash=<script>alert(1)</script>")[2]       # unknown code: nothing is echoed
    assert "alert(1)" not in body and "class='badge ok msg'" not in body
    assert get.raw("/", 'bad"cookie=;;')[0] == 200                       # a malformed Cookie header is ignored


def test_requests_never_touch_the_data_directory(server):
    get, data, snapshot = server
    open_cooldowns()
    post(get, data, {"token": ui.CSRF_TOKEN, "action": "full"})
    post(get, data, {"token": "wrong", "action": "update"})
    assert {p: p.read_bytes() for p in data.rglob("*") if p.is_file()} == snapshot


def test_update_needs_a_full_scan_first(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(ui, "REQUEST_FILE", str(tmp_path / "request.json"))
    past = (dt.datetime.now() - dt.timedelta(minutes=1)).isoformat(timespec="seconds")
    (tmp_path / "state.json").write_text(json.dumps({"loop": True, "next_full_allowed": past,
                                                     "next_update_allowed": past}))
    acts = ui.scan_actions({"running_since": None, "last_full_scan": None})
    assert acts["full"] is None and acts["update"] == "Önce tam tarama gerekiyor."
