import datetime as dt
import json
import os
import sqlite3

import pytest

import sgb_sync as us

NOW = dt.datetime.now()


@pytest.mark.parametrize("raw,exp", [
    ("Evil.com", ("domain", "evil.com")),
    ("https://u:p@Evil.com:8443/", ("domain", "evil.com")),
    ("*.evil.com.", ("domain", "evil.com")),
    ("http://evil.com/Login/Index.php?a=1", ("url", "evil.com/Login/Index.php")),
    ("8.8.4.4:8080", ("ip", "8.8.4.4")),
    ("http://8.8.4.4/x.exe", ("url", "8.8.4.4/x.exe")),
    ("http://[2001:4860::8888]/", ("ipv6", "2001:4860::8888")),
    ("http://[2001:4860::8888]/a", ("url", "[2001:4860::8888]/a")),
    ("2a00:41f::36f", ("ipv6", "2a00:41f::36f")),             # IPv6 without brackets
    ("[2A00:41F:0::36F]", ("ipv6", "2a00:41f::36f")),
    ("2001:db8::1", None),                                     # documentation range, not global
    (" 8.8.8.8 ", ("ip", "8.8.8.8")),
    ("münchen-beispiel.de", ("domain", "xn--mnchen-beispiel-zvb.de")),
    ("192.168.1.1", None), ("10.0.0.1/a", None), ("localhost", None), ("1.2.3.999", None),
    ("-x-.com", None), ("", None), (None, None),
])
def test_classify(raw, exp):
    assert us.classify(raw) == exp


def test_allow_match():
    allow = {"google.com", "1.1.1.1"}
    assert us.allow_match("domain", "docs.google.com", allow) == "google.com"
    assert us.allow_match("url", "docs.google.com/x", allow) == "google.com"
    assert us.allow_match("domain", "notgoogle.com", allow) is None
    assert us.allow_match("ip", "1.1.1.1", allow) == "1.1.1.1"
    assert us.allow_match("url", "1.1.1.1/a", allow) == "1.1.1.1"


# --- Sahte API ---

class Resp:
    def __init__(self, body, code=200):
        self.body, self.status_code = body, code

    def json(self):
        return self.body


class FakeAPI:
    """records: sorted newest to oldest. Behaves like the real API:
    page (1-based request, 0-based "page" in the response), per-page, pageCount, and
    when a page past the end is requested it returns the LAST PAGE again."""
    def __init__(self, records, fail_page=None):
        self.records, self.fail_page, self.calls = records, fail_page, []

    def mount(self, *a):
        pass

    @property
    def headers(self):
        return {}

    def get(self, url, params, timeout):
        page, size = params["page"], params["per-page"]
        self.calls.append(page)
        if page == self.fail_page:
            return Resp({}, 503)
        page_count = max(1, -(-len(self.records) // size))
        served = min(page, page_count)                      # real API: pinned to the last page
        chunk = self.records[(served - 1) * size: served * size]
        return Resp({"models": chunk, "pageCount": page_count, "totalCount": len(self.records),
                     "page": served - 1})


def rec(i, url, days=1):
    return {"id": i, "url": url, "type": "domain", "desc": "PH", "source": "IH", "criticality_level": 4,
            "connectiontype": "PH", "date": (NOW - dt.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S.123")}


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    for name, rel in (("BASE_DIR", ""), ("DB_FILE", "sgb.db"), ("FEED_DIR", "feeds"), ("STATUS_FILE", "status.json"),
                      ("LOG_FILE", "sgb_sync.log"), ("RUN_MARKER", "sgb_sync.running")):
        monkeypatch.setattr(us, name, str(data / rel) if rel else str(data))
    monkeypatch.setattr(us, "ALLOWLIST_FILE", str(tmp_path / "allowlist.txt"))
    monkeypatch.setattr(us, "PAGE_SIZE", 3)
    monkeypatch.setattr(us, "PART_SIZE", 3)
    monkeypatch.setattr(us, "FEED_WINDOWS", [46, 365])
    monkeypatch.setattr(us.time, "sleep", lambda s: None)

    def use(api):
        monkeypatch.setattr(us, "make_session", lambda: api)
        return api

    def feed(name):
        p = data / "feeds" / name
        return p.read_text().split() if p.exists() else None

    def log_lines():
        return (data / "sgb_sync.log").read_text(encoding="utf-8").strip().splitlines()

    return data, use, feed, log_lines


def base_records():
    # newest to oldest; IDs descending
    return [rec(10, "e.com", 1), rec(9, "1.2.3.4", 2), rec(8, "d.com", 50), rec(7, "http://c.com/phish", 100),
            rec(6, "c.com", 200), rec(5, "b.com", 400), rec(4, "a.com", 1000), rec(3, "e.com", 1500),
            rec(2, "5.6.7.8", 1600), rec(1, "192.168.1.1", 1700)]


def test_first_run_full_history(env):
    data, use, feed, log_lines = env
    api = use(FakeAPI(base_records()))
    assert us.main() == 0
    # full history, oldest to newest (by first-seen ID), chunks of 3; e.com is first seen at id=3
    assert feed("domain-part1.txt") == ["e.com", "a.com", "b.com"]
    assert feed("domain-part2.txt") == ["c.com", "d.com"]
    assert feed("domain-part3.txt") is None
    assert feed("ip-part1.txt") == ["5.6.7.8", "1.2.3.4"]
    assert feed("ipv6-part1.txt") == []                        # empty, but the address is stable
    assert feed("url-part1.txt") == ["c.com/phish"]            # c.com is in the domain list with its own record (id=6)
    # Lite windows: records seen in the last N days
    assert feed("domain-46d.txt") == ["e.com"]
    assert feed("domain-365d.txt") == ["e.com", "c.com", "d.com"]   # ordering is still by first-seen ID
    assert feed("ip-46d.txt") == ["1.2.3.4"]
    status = json.loads((data / "status.json").read_text())
    assert status["mode"] == "tam" and status["last_id"] == 10 and status["sgb_records"] == 9
    index = json.loads((data / "feeds" / "index.json").read_text())
    assert {e["name"] for e in index["feeds"]} >= {"domain-part1.txt", "url-part1.txt", "ip-365d.txt"}
    assert "--- Bitti: Başarılı. ---" in log_lines()[-1]


def test_url_host_not_added_to_domain_feed(env):
    data, use, feed, _ = env
    use(FakeAPI([rec(2, "http://only-url.com/login", 1), rec(1, "x.com", 1)]))
    us.main()
    assert "only-url.com" not in feed("domain-part1.txt")
    assert feed("url-part1.txt") == ["only-url.com/login"]


def test_incremental_appends_to_last_part_only(env):
    data, use, feed, _ = env
    records = base_records()
    use(FakeAPI(records))
    us.main()
    part1_before = feed("domain-part1.txt")
    mtime1 = os.path.getmtime(data / "feeds" / "domain-part1.txt")
    api = use(FakeAPI([rec(12, "g.com", 0), rec(11, "f.com", 0)] + records))
    assert us.main() == 0
    assert api.calls == [1]                                    # single page, stopped at a known record
    assert feed("domain-part1.txt") == part1_before            # the previous chunk did not change
    assert os.path.getmtime(data / "feeds" / "domain-part1.txt") == mtime1
    assert feed("domain-part2.txt") == ["c.com", "d.com", "f.com"]
    assert feed("domain-part3.txt") == ["g.com"]
    assert json.loads((data / "status.json").read_text())["mode"] == "artımlı"


def test_allowlist_applies_to_all_feeds(env):
    data, use, feed, _ = env
    (data.parent / "allowlist.txt").write_text("c.com  # critical supplier\n1.2.3.4\n")
    use(FakeAPI(base_records() + []))
    us.main()
    assert "c.com" not in feed("domain-part1.txt") + feed("domain-part2.txt")
    assert feed("url-part1.txt") == []                         # c.com/phish is covered by the allowlist too
    assert feed("ip-part1.txt") == ["5.6.7.8"]
    assert json.loads((data / "status.json").read_text())["allowlisted"] == 3


def test_failed_full_scan_changes_nothing(env):
    data, use, feed, log_lines = env
    use(FakeAPI(base_records(), fail_page=3))
    assert us.main() == 1
    assert not (data / "sgb.db").exists() and not (data / "sgb.db.new").exists()
    assert feed("domain-part1.txt") is None
    assert "Sayfa 3 alınamadı" in log_lines()[-1]


def test_failed_incremental_rolls_back(env):
    data, use, feed, _ = env
    records = base_records()
    use(FakeAPI(records))
    us.main()
    before = feed("domain-part2.txt")
    new = [rec(20 - i, f"n{i}.com", 0) for i in range(5)]
    use(FakeAPI(new + records, fail_page=2))
    assert us.main() == 1
    conn = sqlite3.connect(data / "sgb.db")
    assert conn.execute("SELECT value FROM meta WHERE key='last_id'").fetchone()[0] == "10"
    assert conn.execute("SELECT COUNT(*) FROM records WHERE value LIKE 'n%.com'").fetchone()[0] == 0
    assert feed("domain-part2.txt") == before


def test_weekly_resync_removes_delisted(env, monkeypatch):
    data, use, feed, log_lines = env
    records = base_records()
    use(FakeAPI(records))
    us.main()
    # The source removed b.com (id=5); full scan 8 days later
    monkeypatch.setattr(us.dt, "datetime", type("D", (dt.datetime,), {
        "now": classmethod(lambda c: NOW + dt.timedelta(days=8))}))
    use(FakeAPI([r for r in records if r["id"] != 5]))
    assert us.main() == 0
    assert "b.com" not in feed("domain-part1.txt")
    assert any("SGB listesinden kaldırılan (artık listede olmayan) adres: 1" in l for l in log_lines())
    assert json.loads((data / "status.json").read_text())["mode"] == "tam"


def test_parts_shrink_removes_old_files(env, monkeypatch):
    data, use, feed, _ = env
    use(FakeAPI(base_records()))
    us.main()
    assert feed("domain-part2.txt") is not None
    monkeypatch.setattr(us, "PART_SIZE", 10)
    use(FakeAPI(base_records()))
    us.main()
    assert feed("domain-part2.txt") is None and len(feed("domain-part1.txt")) == 5


def test_page_limit(env, monkeypatch):
    data, use, feed, log_lines = env
    monkeypatch.setattr(us, "MAX_PAGES", 2)
    use(FakeAPI(base_records()))
    assert us.main() == 1
    assert not (data / "sgb.db").exists()
    assert "2 sayfa sınırına ulaşıldı" in log_lines()[-1]


def test_index_html_escapes_and_lists(env):
    data, use, feed, _ = env
    use(FakeAPI(base_records()))
    us.main()
    page = (data / "feeds" / "index.html").read_text(encoding="utf-8")
    assert "domain-part1.txt" in page and "Lite: son 46 gün" in page and "<script" not in page


def test_crashed_writer_is_recovered_without_full_scan(env):
    """A hot journal left by a process killed mid-write is rolled back; no unnecessary full scan."""
    import subprocess
    import sys
    data, use, feed, log_lines = env
    records = base_records()
    use(FakeAPI(records))
    us.main()
    db = str(data / "sgb.db")
    code = ("import sqlite3,os;c=sqlite3.connect(%r);c.execute('PRAGMA cache_size=1');c.execute('BEGIN');"
            "[c.execute(\"INSERT INTO records(id,kind,value) VALUES (?, 'domain', 'z.com')\",(900000+i,)) "
            "for i in range(5000)];os._exit(9)") % db
    subprocess.run([sys.executable, "-c", code])
    assert os.path.exists(db + "-journal")
    api = use(FakeAPI(records))
    assert us.main() == 0
    assert not os.path.exists(db + "-journal")
    assert api.calls == [1]                                   # incremental; not a full scan
    assert any("yarım veritabanı işlemi geri alındı" in l for l in log_lines())
    assert json.loads((data / "status.json").read_text())["mode"] == "artımlı"


# --- HttpClient (urllib, dependency-free) ---

import http.server
import socket
import threading


@pytest.fixture
def http_server(monkeypatch):
    """Local server returning the given (code, body) responses in order. Proxy environment variables are cleared."""
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(us.time, "sleep", lambda s: None)
    state = {"responses": [], "paths": []}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            state["paths"].append(self.path)
            code, body = state["responses"].pop(0) if state["responses"] else (200, b"{}")
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/api", state
    srv.shutdown()
    srv.server_close()


def test_http_retries_then_succeeds(http_server):
    url, state = http_server
    state["responses"] = [(503, b""), (502, b""), (200, b'{"models": [], "pageCount": 0}')]
    r = us.HttpClient().get(url, params={"page": 2, "per-page": 1500})
    assert r.status_code == 200 and r.json() == {"models": [], "pageCount": 0}
    assert len(state["paths"]) == 3 and state["paths"][0] == "/api?page=2&per-page=1500"


def test_http_404_not_retried(http_server):
    url, state = http_server
    state["responses"] = [(404, b"yok")]
    assert us.HttpClient().get(url).status_code == 404 and len(state["paths"]) == 1


def test_http_gives_up_after_retries(http_server):
    url, state = http_server
    state["responses"] = [(503, b"")] * 4
    assert us.HttpClient().get(url).status_code == 503 and len(state["paths"]) == 4


def test_connection_refused_raises(monkeypatch):
    monkeypatch.setattr(us.time, "sleep", lambda s: None)
    for var in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()  # closed port
    with pytest.raises(us.ConnectionFailure):
        us.HttpClient().get(f"http://127.0.0.1:{port}/")


def test_dns_failure_raises(monkeypatch):
    monkeypatch.setattr(us.time, "sleep", lambda s: None)
    for var in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(us.ConnectionFailure):
        us.HttpClient().get("http://olmayan-bir-ad.invalid/")


def test_sync_reports_connection_failure_and_changes_nothing(env, monkeypatch):
    data, use, feed, log_lines = env
    monkeypatch.setattr(us, "API_URL", "http://olmayan-bir-ad.invalid/api")
    for var in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(us, "make_session", lambda: us.HttpClient())
    assert us.main() == 1
    assert "Sayfa 1 alınamadı (bağlantı hatası" in log_lines()[-1] and not (data / "sgb.db").exists()
    assert sum("yeniden denenecek" in l for l in log_lines()) == 3


def test_invalid_json_reported(env, http_server, monkeypatch):
    data, use, feed, log_lines = env
    url, state = http_server
    state["responses"] = [(200, b"<html>bakim</html>")]
    monkeypatch.setattr(us, "API_URL", url)
    monkeypatch.setattr(us, "make_session", lambda: us.HttpClient())
    assert us.main() == 1
    assert "geçersiz (JSON olmayan) yanıt" in log_lines()[-1]


def test_end_to_end_over_real_http(env, http_server, monkeypatch):
    """A real HTTP server instead of the fake API: full scan + feeds."""
    data, use, feed, log_lines = env
    url, state = http_server
    recs = base_records()
    pages = [recs[i:i + 3] for i in range(0, len(recs), 3)] + [[]]
    state["responses"] = [(200, json.dumps({"models": p, "pageCount": 4}).encode()) for p in pages]
    monkeypatch.setattr(us, "API_URL", url)
    monkeypatch.setattr(us, "make_session", lambda: us.HttpClient())
    assert us.main() == 0
    assert feed("domain-part1.txt") == ["e.com", "a.com", "b.com"]



# --- Real API behavior: a page past the end returns the last page again ---

class ClampingAPIWithoutMeta(FakeAPI):
    """An API without pageCount and page fields that still repeats the last page (worst case)."""
    def get(self, url, params, timeout):
        r = super().get(url, params, timeout)
        r.body.pop("pageCount", None)
        r.body.pop("page", None)
        return r


def test_full_scan_stops_at_last_page(env):
    data, use, feed, log_lines = env
    api = use(FakeAPI(base_records()))          # 10 records, pages of 3 -> 4 pages
    assert us.main() == 0
    assert api.calls == [1, 2, 3, 4]           # 5. sayfa istenmedi
    assert any("Listenin sonuna ulaşıldı" in l for l in log_lines())


def test_full_scan_stops_on_repeated_page_without_metadata(env):
    data, use, feed, log_lines = env
    api = use(ClampingAPIWithoutMeta(base_records()))
    assert us.main() == 0
    assert api.calls == [1, 2, 3, 4, 5]        # page 5 = repeat of page 4 -> stopped
    assert any("zaten görülmüş" in l for l in log_lines())
    assert feed("domain-part1.txt") == ["e.com", "a.com", "b.com"]


def test_full_scan_stops_when_api_reports_other_page(env, monkeypatch):
    data, use, feed, log_lines = env

    class PageFieldOnly(FakeAPI):
        def get(self, url, params, timeout):
            r = super().get(url, params, timeout)
            r.body.pop("pageCount", None)
            return r
    api = use(PageFieldOnly(base_records()))
    assert us.main() == 0
    assert api.calls == [1, 2, 3, 4, 5]
    assert any("sayfayı döndürdü (son sayfa)" in l for l in log_lines())


def test_records_added_during_full_scan_are_not_lost(env):
    """If a new record is added at the source during a scan, pages shift: records are re-read, never skipped."""
    data, use, feed, log_lines = env
    records = base_records()

    class Growing(FakeAPI):
        def get(self, url, params, timeout):
            if params["page"] == 2 and not any(r["id"] == 11 for r in self.records):
                self.records.insert(0, rec(11, "yeni.com", 0))   # new record while page 2 is requested
            return super().get(url, params, timeout)
    use(Growing(list(records)))
    assert us.main() == 0
    all_domains = feed("domain-part1.txt") + (feed("domain-part2.txt") or [])
    assert {"e.com", "a.com", "b.com", "c.com", "d.com"} <= set(all_domains)   # none of the old records was skipped
    # the new record (id 11) may not be seen in this scan; the next incremental scan picks it up:
    us.main()
    all_domains = feed("domain-part1.txt") + (feed("domain-part2.txt") or [])
    assert "yeni.com" in all_domains



# --- Real data: IDs do not decrease steadily with date ---

def test_full_scan_with_non_monotonic_ids_reads_everything(env):
    """2026-11 bug: some old records have a higher ID than some newer ones. The scan must not stop early."""
    data, use, feed, log_lines = env
    records = [rec(20, "n1.com", 1), rec(19, "n2.com", 2), rec(18, "n3.com", 3),
               rec(5, "m1.com", 100), rec(4, "m2.com", 101), rec(3, "m3.com", 102),
               rec(30, "old1.com", 1500), rec(29, "old2.com", 1501), rec(28, "old3.com", 1502),  # bulk-loaded old records
               rec(2, "old4.com", 1600), rec(1, "old5.com", 1700)]

    class NoMeta(FakeAPI):  # worst case: no pageCount or page field, only a repeating last page
        def get(self, url, params, timeout):
            r = super().get(url, params, timeout)
            r.body.pop("pageCount", None)
            r.body.pop("page", None)
            return r
    use(NoMeta(records))
    assert us.main() == 0
    domains = set(feed("domain-part1.txt") + feed("domain-part2.txt") + feed("domain-part3.txt") + feed("domain-part4.txt"))
    assert {"old1.com", "old2.com", "old3.com", "old4.com", "old5.com"} <= domains
    assert any("%100.0" in l for l in log_lines())


def test_incomplete_full_scan_is_rejected(env):
    """If the API misreports the page count and the scan ends early, the database is not used."""
    data, use, feed, log_lines = env

    class LyingPageCount(FakeAPI):
        def get(self, url, params, timeout):
            r = super().get(url, params, timeout)
            r.body["pageCount"] = 2      # actually 4 pages
            return r
    use(LyingPageCount(base_records()))
    assert us.main() == 1
    assert not (data / "sgb.db").exists() and feed("domain-part1.txt") is None
    assert "Tam tarama eksik" in log_lines()[-1]


def test_incomplete_full_resync_keeps_existing_data(env, monkeypatch):
    data, use, feed, log_lines = env
    use(FakeAPI(base_records()))
    us.main()
    before = feed("domain-part1.txt")
    monkeypatch.setattr(us.dt, "datetime", type("D", (dt.datetime,), {
        "now": classmethod(lambda c: NOW + dt.timedelta(days=8))}))

    class LyingPageCount(FakeAPI):
        def get(self, url, params, timeout):
            r = super().get(url, params, timeout)
            r.body["pageCount"] = 1
            return r
    use(LyingPageCount(base_records()))
    assert us.main() == 1
    assert feed("domain-part1.txt") == before
    assert json.loads((data / "status.json").read_text())["mode"] == "tam"   # previous successful state


def test_incremental_catches_late_record_on_same_page(env):
    """A new record that lands below a known one (back-dated) is still caught if it is on the same page."""
    data, use, feed, log_lines = env
    records = base_records()
    use(FakeAPI(records))
    us.main()
    late = [rec(12, "en-yeni.com", 0), records[0], rec(11, "geri-tarihli.com", 1)] + records[1:]
    api = use(FakeAPI(late))
    assert us.main() == 0
    assert api.calls == [1]
    domains = feed("domain-part1.txt") + feed("domain-part2.txt") + (feed("domain-part3.txt") or [])
    assert "en-yeni.com" in domains and "geri-tarihli.com" in domains


def test_last_success_is_completion_time(env, monkeypatch):
    """last_success is stamped when the feeds are built, not when the run starts."""
    data, use, feed, _ = env
    use(FakeAPI(base_records()))
    real_build = us.build_feeds

    def slow_build(now, allow):
        monkeypatch.setattr(us.dt, "datetime", type("D", (us.dt.datetime,), {
            "now": classmethod(lambda cls, tz=None: us.dt.datetime(2099, 1, 1, 12, 0, 0))}))
        return real_build(now, allow)

    monkeypatch.setattr(us, "build_feeds", slow_build)
    assert us.main() == 0
    status = json.loads((data / "status.json").read_text())
    index = json.loads((data / "feeds" / "index.json").read_text())
    assert status["last_success"] == "2099-01-01T12:00:00"
    assert index["last_success"] == status["last_success"]
