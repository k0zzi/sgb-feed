"""
SGB malicious-address list -> firewall feeds. Docker version.

The full history is kept in a SQLite database (/data/sgb.db). On every run:
  1. A mode is chosen:
       full scan   - no database yet, or FULL_RESYNC_DAYS have passed since the last full scan.
                     The whole list is fetched into a new database file and swapped in when done,
                     so records the source has removed are dropped as well.
       incremental - new records since the last known ID (usually a single request).
  2. Feeds are regenerated from the database (/data/feeds):
       <kind>-part<N>.txt   full history, oldest to newest, in PART_SIZE chunks (new records go to the last chunk)
       <kind>-<days>d.txt   Lite: records seen in the last <days> days (FEED_WINDOWS)
       index.html / index.json   feed listing: record count, size, last change time
     Kinds: domain, ip (IPv4), ipv6, url (records with a path; their host is not added to the domain list).
  3. Status is written to /data/status.json (for the health check and the UI).

If a scan does not complete (error, page limit, stop signal) the database and feeds are left untouched;
the next scheduled run starts over.
Records are taken as sorted newest to oldest by date; ID order is not relied on (see scan_into).
"""
import datetime as dt
import html
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import sqlite3
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlsplit

# Python standard library only: nothing is downloaded at build time.

# --- SETTINGS (environment variables; see .env.example) ---
BASE_DIR = os.environ.get("SGB_BASE_DIR", "/data")
API_URL = os.environ.get("SGB_API_URL", "https://siberguvenlik.gov.tr/api/address/index")
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "1500"))
PART_SIZE = int(os.environ.get("PART_SIZE", "128000"))
FEED_WINDOWS = sorted({int(x) for x in os.environ.get("FEED_WINDOWS", "46,90,180,365").split(",") if x.strip()})
FULL_RESYNC_DAYS = int(os.environ.get("FULL_RESYNC_DAYS", "7"))   # 0: disabled
SYNC_INTERVAL_MINUTES = int(os.environ.get("SYNC_INTERVAL_MINUTES", "0"))  # 0: run once and exit
MAX_PAGES = int(os.environ.get("MAX_PAGES", "2000"))             # safety limit
COMPLETENESS_RATIO = float(os.environ.get("COMPLETENESS_RATIO", "0.99"))  # share of reported records a full scan must see
EMPTY_PAGE_ATTEMPTS = 3            # full scan: requests per page that comes back empty before pageCount
EMPTY_PAGE_WAITS = (2, 4)          # seconds to wait before the 2nd and 3rd request
MAX_CONSECUTIVE_SKIPS = 3          # full scan stops after this many skipped pages in a row
ALLOWLIST_FILE = os.environ.get("ALLOWLIST_FILE", "/config/allowlist.txt")
CONTROL_DIR = os.environ.get("SGB_CONTROL_DIR", "/control")   # shared with the UI: scan requests and state
FULL_REQUEST_COOLDOWN_MINUTES = 60     # a requested full scan needs 60 min since the last full scan attempt
UPDATE_REQUEST_COOLDOWN_MINUTES = 5    # a requested update needs 5 min since the last run
REQUEST_POLL_SECONDS = 5               # how often the waiting loop looks for a request

DB_FILE = os.path.join(BASE_DIR, "sgb.db")
FEED_DIR = os.path.join(BASE_DIR, "feeds")
STATUS_FILE = os.path.join(BASE_DIR, "status.json")
LOG_FILE = os.path.join(BASE_DIR, "sgb_sync.log")
RUN_MARKER = os.path.join(BASE_DIR, "sgb_sync.running")
REQUEST_FILE = os.path.join(CONTROL_DIR, "request.json")
STATE_FILE = os.path.join(CONTROL_DIR, "state.json")

KINDS = ("domain", "ip", "ipv6", "url")
LITE_KINDS = ("domain", "ip")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
FEED_NAME_RE = re.compile(r"^(?:domain|ip|ipv6|url)-(?:part\d+|\d+d)\.txt$")
log = logging.getLogger("sgb")

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id          INTEGER PRIMARY KEY,   -- source record ID
    kind        TEXT NOT NULL,         -- domain | ip | ipv6 | url
    value       TEXT NOT NULL,         -- normalized value (what goes into the feed)
    date        TEXT,                  -- source date, YYYY-MM-DD HH:MM:SS
    raw         TEXT,                  -- raw 'url' field as published
    sgb_type    TEXT,
    descr       TEXT,
    source      TEXT,
    criticality INTEGER,
    conntype    TEXT
);
CREATE INDEX IF NOT EXISTS ix_feed ON records(kind, value, id, date);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


# --- PARSING ---

def classify(raw):
    """Turns the source 'url' field into (kind, value); None if invalid or a non-public IP."""
    s = (raw or "").strip()
    if not s:
        return None
    # Bare IP (notably IPv6 without brackets): parsed as a URL, "2a00:41f::36f" would be read as
    # host="2a00", port="41f::36f". Try it as a plain IP first.
    try:
        ip = ipaddress.ip_address(s.removeprefix("[").removesuffix("]"))
        if not ip.is_global:
            return None
        return ("ip" if ip.version == 4 else "ipv6"), ip.compressed
    except ValueError:
        pass
    try:
        parts = urlsplit(s if "://" in s else "http://" + s)
        host = parts.hostname  # lower-cased; port, userinfo and brackets are dropped
    except ValueError:
        return None
    host = (host or "").rstrip(".").removeprefix("*.")
    path = parts.path if parts.path not in ("", "/") else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            return None  # never 10.x, 192.168.x, loopback, etc.
        if path:
            return "url", (f"[{ip.compressed}]" if ip.version == 6 else ip.compressed) + path
        return ("ip" if ip.version == 4 else "ipv6"), ip.compressed
    try:
        host = host.encode("idna").decode("ascii")  # non-ASCII domain names -> punycode
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or labels[-1].isdigit() or not all(LABEL_RE.match(l) for l in labels):
        return None
    return ("url", host + path) if path else ("domain", host)


def parse_date(s):
    try:
        return dt.datetime.strptime(str(s).split(".")[0].replace("T", " "), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def load_allowlist():
    if not os.path.exists(ALLOWLIST_FILE):
        return set()
    with open(ALLOWLIST_FILE, encoding="utf-8") as f:
        return {l.split("#")[0].strip().lower().removeprefix("*.").rstrip(".") for l in f} - {""}


def allow_match(kind, value, allow):
    """Returns the allowlist entry that exempts the value from blocking (None if none). Domain entries cover subdomains."""
    if not allow:
        return None
    host = value
    if kind == "url":
        host = value.split("/", 1)[0]
        if host.startswith("["):
            host = host[1:host.index("]")]
    if host in allow:
        return host
    try:
        ipaddress.ip_address(host)
        return None  # IPs match exactly only
    except ValueError:
        pass
    labels = host.split(".")
    for i in range(1, len(labels)):
        cand = ".".join(labels[i:])
        if cand in allow:
            return cand
    return None


# --- FILE WRITING ---

def atomic_write(path, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp_")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o644)  # nginx and the UI read this as different users
    os.replace(tmp, path)


# --- SCAN REQUESTS FROM THE UI (/control) ---
# The UI cannot touch /data. It can only drop request.json into /control; this service decides whether
# to run it and publishes its timings in state.json so the UI can show which button is available.

_state = {"loop": False, "last_run_started": None, "last_full_started": None}


def write_state():
    """Best effort: a missing or read-only /control must never break a sync run."""
    s = dict(_state, interval_minutes=SYNC_INTERVAL_MINUTES,
             full_cooldown_minutes=FULL_REQUEST_COOLDOWN_MINUTES,
             update_cooldown_minutes=UPDATE_REQUEST_COOLDOWN_MINUTES,
             updated=dt.datetime.now().isoformat(timespec="seconds"))
    for key, minutes in (("next_full_allowed", FULL_REQUEST_COOLDOWN_MINUTES),
                         ("next_update_allowed", UPDATE_REQUEST_COOLDOWN_MINUTES)):
        base = _state["last_full_started"] if key == "next_full_allowed" else _state["last_run_started"]
        s[key] = ((dt.datetime.fromisoformat(base) + dt.timedelta(minutes=minutes)).isoformat(timespec="seconds")
                  if base else None)
    try:
        os.makedirs(CONTROL_DIR, exist_ok=True)
        atomic_write(STATE_FILE, json.dumps(s, ensure_ascii=False, indent=1))
    except OSError as e:
        log.warning(f"Kontrol durumu yazılamadı ({STATE_FILE}): {e}")


def load_state():
    """Restores the timings after a restart, so a restart does not reset the cooldowns."""
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            old = json.load(f)
    except (OSError, ValueError):
        return
    for key in ("last_run_started", "last_full_started"):
        try:
            if old.get(key):
                _state[key] = dt.datetime.fromisoformat(old[key]).isoformat(timespec="seconds")
        except (TypeError, ValueError):
            pass


def note_run_start(mode, now):
    _state["last_run_started"] = now.isoformat(timespec="seconds")
    if mode == "full":
        _state["last_full_started"] = _state["last_run_started"]
    write_state()


def take_request():
    """Reads and removes request.json. Returns a valid request dict or None."""
    try:
        with open(REQUEST_FILE, encoding="utf-8") as f:
            raw = f.read(4096)
    except FileNotFoundError:
        return None
    except OSError as e:
        log.warning(f"Tarama isteği okunamadı: {e}")
        return None
    try:
        os.remove(REQUEST_FILE)
    except OSError:
        pass
    try:
        req = json.loads(raw)
    except ValueError:
        req = None
    if not isinstance(req, dict) or req.get("mode") not in ("full", "incremental"):
        log.warning("Geçersiz tarama isteği yok sayıldı.")
        return None
    clean = lambda v: re.sub(r"[^\w.:@\-]", "", str(v or "-"))[:64] or "-"
    return {"mode": req["mode"], "by": clean(req.get("by")), "ip": clean(req.get("ip"))}


def db_has_full_scan():
    if not os.path.exists(DB_FILE):
        return False
    try:
        conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=30)
        try:
            return bool(get_meta(conn, "last_full_scan"))
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return False


def request_verdict(req, now):
    """(mode to run, None) or (None, reason it was refused). Enforced here, not only in the UI."""
    mode = req["mode"]
    if mode == "incremental" and not db_has_full_scan():
        mode = "full"   # nothing to update yet
    if mode == "full":
        base, minutes = _state["last_full_started"], FULL_REQUEST_COOLDOWN_MINUTES
    else:
        base, minutes = _state["last_run_started"], UPDATE_REQUEST_COOLDOWN_MINUTES
    if base:
        allowed = dt.datetime.fromisoformat(base) + dt.timedelta(minutes=minutes)
        if now < allowed:
            what = "tam tarama" if mode == "full" else "güncelleme"
            return None, f"{what} saat {allowed.strftime('%H:%M')} sonrasında istenebilir"
    return mode, None


# --- API ---

class ConnectionFailure(Exception):
    """The server could not be reached even after retries (DNS, timeout, connection refused, etc.)."""


class HttpResponse:
    def __init__(self, status_code, content):
        self.status_code, self.content = status_code, content

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class HttpClient:
    """Dependency-free HTTP client (urllib).
    - Retries transient failures (connection, timeout, HTTP 429/5xx) with growing delays: 2, 4, 8 s.
    - Corporate proxy: honors the HTTPS_PROXY / NO_PROXY environment variables.
    - Certificate verification is on (system CA store)."""
    RETRY_STATUS = {429, 500, 502, 503, 504}

    def __init__(self, retries=3, backoff=2.0):
        self.retries, self.backoff = retries, backoff
        self.opener = urllib.request.build_opener()  # ProxyHandler reads the environment variables

    def get(self, url, params=None, timeout=60):
        full = url + ("?" + urllib.parse.urlencode(params) if params else "")
        req = urllib.request.Request(full, headers={"User-Agent": "sgb-feed/2.0", "Accept": "application/json"})
        last = None
        for attempt in range(self.retries + 1):
            if attempt:
                wait = self.backoff * 2 ** (attempt - 1)
                log.warning(f"İstek başarısız ({last}); {wait:.0f} sn sonra yeniden denenecek "
                            f"({attempt}/{self.retries}).")
                time.sleep(wait)
            try:
                with self.opener.open(req, timeout=timeout) as r:
                    return HttpResponse(r.status, r.read())
            except urllib.error.HTTPError as e:  # the server answered but not with 2xx
                body = e.read()
                if e.code not in self.RETRY_STATUS or attempt == self.retries:
                    return HttpResponse(e.code, body)
                last = f"HTTP {e.code}"
            except (OSError, http.client.HTTPException) as e:  # DNS, timeout, connection dropped
                last = getattr(e, "reason", None) or e
                if attempt == self.retries:
                    raise ConnectionFailure(str(last)) from e
        raise ConnectionFailure(str(last))


def make_session():
    return HttpClient()


def fetch_page(session, page):
    started = time.monotonic()
    try:
        resp = session.get(API_URL, params={"page": page, "per-page": PAGE_SIZE}, timeout=60)
    except ConnectionFailure as e:
        raise RuntimeError(f"Sayfa {page} alınamadı (bağlantı hatası: {e}); hiçbir dosya değiştirilmedi.") from e
    elapsed = time.monotonic() - started
    if resp.status_code != 200:
        raise RuntimeError(f"Sayfa {page} alınamadı (HTTP {resp.status_code}); hiçbir dosya değiştirilmedi.")
    try:
        body = resp.json()
    except ValueError as e:
        raise RuntimeError(f"Sayfa {page}: API geçersiz (JSON olmayan) yanıt döndürdü; "
                           f"hiçbir dosya değiştirilmedi.") from e
    # The 0-based "page", "pageCount" and "totalCount" of the response are returned too;
    # scan_into uses them to recognize the end of the list.
    return {"models": body.get("models") or [], "page_count": body.get("pageCount"),
            "total": body.get("totalCount"), "resp_page": body.get("page"), "elapsed": elapsed}


# --- SCANNING ---

def connect(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.executescript(SCHEMA)
    return conn


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def scan_into(conn, session, stop_id):
    """Reads newest to oldest and adds records to conn (does not commit). stop_id=0: full scan.

    Cases handled:
      - Records are taken as sorted newest first by date. ID order is not relied on: an older
        record may have a higher ID than a newer one.
      - A request past the end may return the last page again instead of an empty list.
      - A page inside the list (page <= pageCount) may come back empty; see the retry rule below.
    The end of the list is recognized by any of these signals:
      1. the page number in the response differs from the one requested (pinned to the last page),
      2. pageCount was reached (using the current value from every response),
      3. more than 90% of the records on the page were already seen in this scan (repeated last page).
    In an incremental scan (stop_id > 0) every page is processed whole; records with an ID above
    stop_id are added, and the scan stops after the first page that contains a known record. Late-added
    records that land on the same page are caught that way; older ones are picked up by the weekly full scan.
    In a full scan, an empty page with page <= pageCount is requested EMPTY_PAGE_ATTEMPTS times in total;
    if it stays empty it is skipped and the scan goes on. After MAX_CONSECUTIVE_SKIPS skipped pages in a
    row the scan stops. Skipped pages are returned in "skipped_pages". In an incremental scan an empty
    page still ends the scan.
    In a full scan, if the number of unique records seen is below COMPLETENESS_RATIO times the
    totalCount reported at the start, the scan counts as incomplete and RuntimeError is raised.
    Records added while the scan runs shift the pages; this only causes a few records to be read
    twice, never skipped.
    """
    page, highest, added, invalid = 1, stop_id, 0, 0
    seen, start_total = set(), None
    skipped, consecutive_skips, known_page_count = [], 0, None
    while True:
        if page > MAX_PAGES:
            raise RuntimeError(f"{MAX_PAGES} sayfa sınırına ulaşıldı; hiçbir dosya değiştirilmedi.")
        r = fetch_page(session, page)
        models, page_count, elapsed = r["models"], r["page_count"], r["elapsed"]
        if start_total is None and isinstance(r["total"], int):
            start_total = r["total"]
        if isinstance(page_count, int):
            known_page_count = page_count
        elif not models and known_page_count:
            page_count = known_page_count    # a faulty empty response may come without metadata
        if not models and stop_id == 0 and isinstance(page_count, int) and page <= page_count:
            # An empty page inside the list is a transient API fault: ask again, then skip it.
            for attempt in range(1, EMPTY_PAGE_ATTEMPTS + 1):
                detail = (f"API yanıtı: page={r['resp_page']}, pageCount={r['page_count']}, "
                          f"totalCount={r['total']}; {r['elapsed']:.1f} sn")
                if attempt == EMPTY_PAGE_ATTEMPTS:
                    log.warning(f"Sayfa {page}/{page_count} boş döndü (deneme {attempt}/{EMPTY_PAGE_ATTEMPTS}; {detail}).")
                    break
                wait = EMPTY_PAGE_WAITS[min(attempt - 1, len(EMPTY_PAGE_WAITS) - 1)]
                log.warning(f"Sayfa {page}/{page_count} boş döndü (deneme {attempt}/{EMPTY_PAGE_ATTEMPTS}; {detail}). "
                            f"{wait} sn sonra tekrar istenecek.")
                time.sleep(wait)
                r = fetch_page(session, page)
                models, elapsed = r["models"], r["elapsed"]
                if isinstance(r["page_count"], int):
                    page_count = known_page_count = r["page_count"]
                if models:
                    log.info(f"Sayfa {page}: {attempt + 1}. denemede kayıtlarla döndü, devam ediliyor.")
                    break
            if not models:
                skipped.append(page)
                consecutive_skips += 1
                log.warning(f"Sayfa {page} {EMPTY_PAGE_ATTEMPTS} denemede de boş döndü, ATLANDI. Bu sayfadaki kayıtlar "
                            f"bir sonraki tam taramaya kadar eksik kalabilir.")
                if consecutive_skips >= MAX_CONSECUTIVE_SKIPS:
                    log.warning(f"Art arda {consecutive_skips} sayfa atlandı (sayfa {', '.join(map(str, skipped[-consecutive_skips:]))}); "
                                f"tarama durduruluyor, bütünlük kontrolü karar verecek.")
                    break
                if page >= page_count:
                    break
                page += 1
                time.sleep(0.2)
                continue
        if not models:
            log.info(f"Sayfa {page} ({elapsed:.1f} sn): boş. Listenin sonuna ulaşıldı.")
            break
        if isinstance(r["resp_page"], int) and r["resp_page"] != page - 1:
            log.info(f"Sayfa {page}: API {r['resp_page'] + 1}. sayfayı döndürdü (son sayfa). Listenin sonuna ulaşıldı.")
            break
        ids = [m.get("id") for m in models if isinstance(m.get("id"), int) and not isinstance(m.get("id"), bool)]
        if seen and ids and sum(i in seen for i in ids) / len(ids) > 0.9:
            log.info(f"Sayfa {page}: kayıtların çoğu bu taramada zaten görülmüş (API son sayfayı tekrarlıyor). "
                     f"Listenin sonuna ulaşıldı.")
            break
        consecutive_skips = 0
        rows, known = [], 0
        for m in models:
            item_id = m.get("id")
            if not isinstance(item_id, int) or isinstance(item_id, bool):
                invalid += 1
                continue
            if item_id in seen:          # record seen twice because of page shift
                continue
            seen.add(item_id)
            if stop_id and item_id <= stop_id:
                known += 1
                continue
            highest = max(highest, item_id)
            c = classify(m.get("url"))
            if c is None:
                invalid += 1
                continue
            d = parse_date(m.get("date"))
            crit = m.get("criticality_level")
            rows.append((item_id, c[0], c[1], d.strftime("%Y-%m-%d %H:%M:%S") if d else None,
                         str(m.get("url"))[:2000], m.get("type"), m.get("desc"), m.get("source"),
                         crit if isinstance(crit, int) else None, m.get("connectiontype")))
        conn.executemany("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
        added += len(rows)
        oldest = min((parse_date(m.get("date")) for m in models if parse_date(m.get("date"))), default=None)
        msg = f"Sayfa {page}"
        if stop_id == 0 and isinstance(page_count, int) and page_count:
            msg += f"/{page_count} (ilerleme: %{min(100, int(page / page_count * 100))})"
        msg += f" ({elapsed:.1f} sn): {len(rows)} {'yeni ' if stop_id else ''}kayıt"
        if oldest:
            msg += f", en eski tarih {oldest:%Y-%m-%d}"
        if stop_id and known:
            log.info(msg + ". Bilinen kayıtlara ulaşıldı.")
            break
        if stop_id == 0 and isinstance(page_count, int) and page >= page_count:
            log.info(msg + ". Listenin sonuna ulaşıldı.")
            break
        log.info(msg + ".")
        page += 1
        time.sleep(0.2)

    if skipped:
        log.warning(f"Atlanan sayfalar: {', '.join(map(str, skipped))}.")
    if stop_id == 0 and start_total:
        ratio = len(seen) / start_total
        log.info(f"Bütünlük kontrolü: API {start_total} kayıt bildirdi, taramada {len(seen)} benzersiz kayıt görüldü "
                 f"(%{ratio * 100:.1f}).")
        if ratio < COMPLETENESS_RATIO:
            raise RuntimeError(f"Tam tarama eksik: API {start_total} kayıt bildiriyor, yalnızca {len(seen)} kayıt "
                               f"görüldü (%{ratio * 100:.1f})"
                               + (f", atlanan sayfa: {', '.join(map(str, skipped))}" if skipped else "")
                               + ". Mevcut veri ve feed'ler korundu; sonraki çalıştırma tekrar deneyecek.")
    return {"pages": page, "added": added, "invalid": invalid, "highest": highest,
            "seen": len(seen), "total": start_total, "skipped_pages": skipped}


def distinct_count(conn, schema="main"):
    return conn.execute(f"SELECT COUNT(*) FROM (SELECT DISTINCT kind, value FROM {schema}.records)").fetchone()[0]


def full_scan(session, now, reason):
    """Fetches the whole list into a new database; on success it replaces the old one."""
    log.info(f"Tam tarama başlıyor ({reason}). Sayfa boyutu {PAGE_SIZE}; bu işlem birkaç on dakika sürebilir.")
    tmp_db = DB_FILE + ".new"
    for p in (tmp_db, tmp_db + "-journal"):
        if os.path.exists(p):
            os.remove(p)
    conn = connect(tmp_db)
    try:
        stats = scan_into(conn, session, 0)
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_id', ?), ('last_full_scan', ?), ('skipped_pages', ?)",
                     (str(stats["highest"]), now.isoformat(timespec="seconds"), json.dumps(stats["skipped_pages"])))
        conn.commit()
        if os.path.exists(DB_FILE):
            conn.execute("ATTACH DATABASE ? AS old", (DB_FILE,))
            removed = conn.execute(
                "SELECT COUNT(*) FROM (SELECT DISTINCT kind, value FROM old.records "
                "EXCEPT SELECT DISTINCT kind, value FROM main.records)").fetchone()[0]
            conn.execute("DETACH DATABASE old")
            stats["removed"] = removed
        conn.close()
    except BaseException:
        conn.close()
        for p in (tmp_db, tmp_db + "-journal"):
            if os.path.exists(p):
                os.remove(p)
        raise
    os.chmod(tmp_db, 0o644)
    os.replace(tmp_db, DB_FILE)
    stats["mode"] = "tam"
    msg = (f"Tam tarama tamam: {stats['pages']} sayfa, {stats['added']} kayıt, "
           f"{stats['invalid']} geçersiz.")
    if "removed" in stats:
        msg += f" SGB listesinden kaldırılan (artık listede olmayan) adres: {stats['removed']}."
    if stats["skipped_pages"]:
        msg += f" Atlanan sayfa ({len(stats['skipped_pages'])}): {', '.join(map(str, stats['skipped_pages']))}."
    log.info(msg)
    return stats


def incremental(session):
    conn = connect(DB_FILE)
    try:
        last_id = int(get_meta(conn, "last_id", "0"))
        log.info(f"Artımlı tarama (son bilinen ID: {last_id})...")
        stats = scan_into(conn, session, last_id)
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_id', ?)", (str(stats["highest"]),))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    stats["mode"] = "artımlı"
    log.info(f"Artımlı tarama tamam: {stats['pages']} sayfa, {stats['added']} yeni kayıt, "
             f"{stats['invalid']} geçersiz.")
    return stats


def recover_db():
    """If the previous run was killed mid-write, rolls back the leftover half transaction (hot journal).
    Without this the read-only UI cannot read the database. Opening a read-write connection is enough."""
    if not os.path.exists(DB_FILE):
        return
    journal = DB_FILE + "-journal"
    had_journal = os.path.exists(journal)
    conn = sqlite3.connect(DB_FILE, timeout=30)
    try:
        conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
    finally:
        conn.close()
    if had_journal and not os.path.exists(journal):
        log.warning("Önceki çalıştırmadan kalan yarım veritabanı işlemi geri alındı.")
    # Temp file of an unfinished full scan
    for p in (DB_FILE + ".new", DB_FILE + ".new-journal"):
        if os.path.exists(p):
            os.remove(p)


def choose_mode(now):
    if not os.path.exists(DB_FILE):
        return "full", "ilk çalıştırma"
    conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=30)
    try:
        last_full = get_meta(conn, "last_full_scan")
    except sqlite3.DatabaseError:
        last_full = None
    finally:
        conn.close()
    if not last_full:
        return "full", "veritabanında tam tarama kaydı yok"
    if FULL_RESYNC_DAYS > 0 and now - dt.datetime.fromisoformat(last_full) >= dt.timedelta(days=FULL_RESYNC_DAYS):
        return "full", f"son tam taramanın üzerinden {FULL_RESYNC_DAYS} gün geçti; kaldırılan kayıtlar temizlenecek"
    return "incremental", ""


# --- FEED GENERATION ---

def build_feeds(now, allow):
    """Builds all feed contents from the database: {file_name: (kind, scope, days, lines)}."""
    feeds, stats = {}, {"allowlisted": 0, "per_kind": {}}
    conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=30)
    try:
        for kind in KINDS:
            rows = conn.execute("SELECT value FROM records WHERE kind = ? GROUP BY value ORDER BY MIN(id)",
                                (kind,)).fetchall()
            values = []
            for (v,) in rows:
                if allow_match(kind, v, allow):
                    stats["allowlisted"] += 1
                else:
                    values.append(v)
            stats["per_kind"][kind] = len(values)
            n_parts = max(1, -(-len(values) // PART_SIZE))
            for i in range(n_parts):
                feeds[f"{kind}-part{i + 1}.txt"] = (kind, "tam", None, values[i * PART_SIZE:(i + 1) * PART_SIZE])
        for days in FEED_WINDOWS:
            cutoff = (now - dt.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            for kind in LITE_KINDS:
                rows = conn.execute("SELECT value FROM records WHERE kind = ? GROUP BY value "
                                    "HAVING MAX(date) >= ? ORDER BY MIN(id)", (kind, cutoff)).fetchall()
                values = [v for (v,) in rows if not allow_match(kind, v, allow)]
                if len(values) > PART_SIZE:
                    log.warning(f"{kind}-{days}d.txt {len(values)} kayıt; PART_SIZE ({PART_SIZE}) sınırını aşıyor.")
                feeds[f"{kind}-{days}d.txt"] = (kind, "lite", days, values)
    finally:
        conn.close()
    return feeds, stats


def write_feeds(feeds, now, status):
    os.makedirs(FEED_DIR, exist_ok=True)
    changed = []
    for name, (_, _, _, values) in feeds.items():
        data = ("\n".join(values) + ("\n" if values else "")).encode("utf-8")
        path = os.path.join(FEED_DIR, name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                if f.read() == data:
                    continue
        atomic_write(path, data)
        changed.append(name)
    # Delete feeds that are no longer produced (e.g. fewer chunks, a window was removed)
    for name in os.listdir(FEED_DIR):
        if FEED_NAME_RE.match(name) and name not in feeds:
            os.remove(os.path.join(FEED_DIR, name))
            changed.append(f"{name} (silindi)")

    entries = []
    for name, (kind, scope, days, values) in feeds.items():
        path = os.path.join(FEED_DIR, name)
        entries.append({"name": name, "kind": kind, "scope": scope, "days": days, "lines": len(values),
                        "bytes": os.path.getsize(path),
                        "updated": dt.datetime.fromtimestamp(os.path.getmtime(path)).isoformat(timespec="seconds")})
    order = {k: i for i, k in enumerate(KINDS)}
    entries.sort(key=lambda e: (order[e["kind"]], e["scope"] != "tam", e["days"] or 0, e["name"]))
    index = {"generated": now.isoformat(timespec="seconds"), "last_success": status["last_success"],
             "part_size": PART_SIZE, "feeds": entries}
    atomic_write(os.path.join(FEED_DIR, "index.json"), json.dumps(index, ensure_ascii=False, indent=1))
    atomic_write(os.path.join(FEED_DIR, "index.html"), render_index(index))
    return changed


def num(n):
    return f"{n:,}".replace(",", ".")


def human_size(n):
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024


def render_index(index):
    titles = {"domain": "Domain", "ip": "IPv4", "ipv6": "IPv6", "url": "URL"}
    rows = []
    for e in index["feeds"]:
        scope = "Tam liste" if e["scope"] == "tam" else f"Lite: son {e['days']} gün"
        rows.append(f"<tr><td>{html.escape(titles[e['kind']])}</td><td>{scope}</td>"
                    f"<td><a href='{html.escape(e['name'])}'>{html.escape(e['name'])}</a></td>"
                    f"<td class='n'>{num(e['lines'])}</td><td class='n'>{human_size(e['bytes'])}</td>"
                    f"<td>{html.escape(e['updated'].replace('T', ' '))}</td></tr>")
    return f"""<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>SGB Feed Listesi</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>
body{{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1d2330}}
header{{background:#1d2330;color:#fff;padding:14px 24px}}h1{{font-size:18px;margin:0;font-weight:600}}
main{{max-width:1100px;margin:20px auto;padding:0 20px}}.card{{background:#fff;border:1px solid #e2e5ea;border-radius:8px;padding:16px 20px;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #eceef2}}
th{{color:#5c6475}}td.n{{text-align:right;font-variant-numeric:tabular-nums}}.muted{{color:#5c6475;font-size:13px}}
</style></head><body><header><h1>SGB Feed Listesi</h1></header><main>
<div class="card"><p class="muted">Son başarılı senkronizasyon: {html.escape(index['last_success'].replace('T', ' '))} ·
Parça boyutu: {num(index['part_size'])} satır · Kaynak: SGB</p>
<p class="muted">Tam liste: SGB'nin yayımladığı tüm kayıtlar, en eskiden yeniye parçalanmış; yeni kayıtlar son parçaya eklenir.
Lite: yalnızca son N günde SGB listesinde görülen kayıtlar (düşük kapasiteli cihazlar için).
URL feed'i yol içeren kayıtları içerir; Web Filter URL listesi olarak kullanılır.</p></div>
<div class="card"><table><tr><th>Tür</th><th>Kapsam</th><th>Dosya</th><th class="n">Satır</th><th class="n">Boyut</th><th>Son değişiklik</th></tr>
{''.join(rows)}</table></div></main></body></html>"""


# --- MAIN FLOW ---

def run(forced=None):
    """forced: None (automatic) or a request dict from take_request() whose mode was already checked."""
    os.makedirs(FEED_DIR, exist_ok=True)
    now = dt.datetime.now()
    started = time.monotonic()
    allow = load_allowlist()
    session = make_session()

    recover_db()
    mode, reason = choose_mode(now)
    if forced:
        who = f"kullanıcı isteği: arayüz, {forced['by']}, {forced['ip']}"
        if forced["mode"] == "full":
            mode, reason = "full", who
        elif mode == "incremental":
            log.info(f"Güncelleme ({who}).")
    note_run_start(mode, now)
    stats = full_scan(session, now, reason) if mode == "full" else incremental(session)

    conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=30)
    try:
        total_rows = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        last_id = int(get_meta(conn, "last_id", "0"))
        last_full = get_meta(conn, "last_full_scan")
        try:
            skipped_pages = json.loads(get_meta(conn, "skipped_pages", "[]"))
        except ValueError:
            skipped_pages = []
    finally:
        conn.close()

    status = {"last_success": None, "mode": stats["mode"],
              "last_id": last_id, "last_full_scan": last_full, "sgb_records": total_rows,
              "added": stats["added"], "removed": stats.get("removed"), "pages": stats["pages"],
              "page_size": PAGE_SIZE, "feed_windows": FEED_WINDOWS, "full_resync_days": FULL_RESYNC_DAYS,
              "skipped_pages": skipped_pages}
    feeds, fstats = build_feeds(now, allow)
    # last_success is the time the run finished building the feeds, not the time it started: a full
    # scan takes ~20 minutes, and the feed index and files must agree with this timestamp.
    status["last_success"] = dt.datetime.now().isoformat(timespec="seconds")
    changed = write_feeds(feeds, now, status)
    status.update({"feed_counts": fstats["per_kind"], "allowlisted": fstats["allowlisted"],
                   "duration_seconds": round(time.monotonic() - started, 1)})
    atomic_write(STATUS_FILE, json.dumps(status, ensure_ascii=False, indent=1))

    counts = ", ".join(f"{k}: {v}" for k, v in fstats["per_kind"].items())
    log.info(f"Feed'ler: {counts}; allowlist nedeniyle çıkarılan: {fstats['allowlisted']}.")
    log.info(f"Değişen feed dosyaları: {', '.join(changed) if changed else 'yok'}.")


_stop_requested = False


def _stop_signal(signum, frame):
    global _stop_requested
    _stop_requested = True
    raise KeyboardInterrupt


def main(forced=None):
    os.makedirs(BASE_DIR, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
                        force=True)
    for name in ("SIGBREAK", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stop_signal)

    log.info("--- SGB senkronizasyonu başladı ---")
    if os.path.exists(RUN_MARKER):
        with open(RUN_MARKER, encoding="utf-8") as f:
            started = f.read().strip() or "bilinmiyor"
        log.warning(f"Önceki çalıştırma (başlangıç: {started}) düzgün bitmedi: süreç zorla sonlandırılmış "
                    f"(docker kill, kapanma vb.). Yarım tarama kaydedilmemişti, bu çalıştırma normal şekilde devam ediyor.")
    with open(RUN_MARKER, "w", encoding="utf-8") as f:
        f.write(dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    code = 1
    try:
        run(forced)
        log.info("--- Bitti: Başarılı. ---")
        code = 0
    except KeyboardInterrupt:
        log.error("--- Bitti: Kullanıcı tarafından durduruldu. ---")
    except RuntimeError as e:
        log.error(f"--- Bitti: {e} ---")
    except Exception as e:
        log.exception("Ayrıntı:")
        log.error(f"--- Bitti: Hata: {e} ---")
    finally:
        if os.path.exists(RUN_MARKER):
            os.remove(RUN_MARKER)
    return code


def loop():
    """Container mode: run now, then repeat every SYNC_INTERVAL_MINUTES minutes or on a request from the UI."""
    for name in ("SIGINT", "SIGBREAK", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stop_signal)
    _state["loop"] = True
    load_state()
    forced = None
    while True:
        main(forced)
        if _stop_requested:
            log.info("Senkronizasyon servisi kapanıyor.")
            return 0
        try:
            log.info(f"Sonraki çalıştırma {SYNC_INTERVAL_MINUTES} dakika sonra.")
            write_state()
            forced = wait_for_next_run(SYNC_INTERVAL_MINUTES * 60)
        except KeyboardInterrupt:
            log.info("Durdurma sinyali alındı, senkronizasyon servisi kapanıyor.")
            return 0


def wait_for_next_run(seconds):
    """Sleeps until the next scheduled run, waking early for a valid request from the UI.
    Returns the request to run, or None for the scheduled run."""
    deadline = time.monotonic() + seconds
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        time.sleep(min(REQUEST_POLL_SECONDS, left))
        req = take_request()
        if not req:
            continue
        what = "tam tarama" if req["mode"] == "full" else "güncelleme"
        mode, refused = request_verdict(req, dt.datetime.now())
        if refused:
            log.warning(f"Arayüzden gelen {what} isteği reddedildi ({req['by']}, {req['ip']}): {refused}.")
            continue
        req["mode"] = mode
        log.info(f"Arayüzden {what} isteği alındı ({req['by']}, {req['ip']}); başlatılıyor.")
        return req


if __name__ == "__main__":
    sys.exit(loop() if SYNC_INTERVAL_MINUTES > 0 else main())
