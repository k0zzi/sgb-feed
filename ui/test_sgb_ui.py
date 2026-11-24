"""UI tests: builds the database with the real sgb_sync (fake API) and runs the UI as a live server."""
import datetime as dt
import json
import os
import sys
import threading
import urllib.error
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
