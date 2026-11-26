# sgb-feed

A Docker-based tool that keeps the **entire** malicious-address list published by SGB on your own server, refreshes it hourly, and turns it into **partitioned feeds** that firewalls can pull directly. It includes a **read-only lookup UI** for analysts.

> The web UI and the log messages are in Turkish. Everything else (documentation, configuration, code comments) is in English.

- The full history (~500,000 records) is kept in a SQLite database.
- Feeds are split by kind: **domain**, **IPv4**, **IPv6**, **URL**.
- The full list is split into **128,000-line chunks**, so that each file stays small enough for firewalls that cap the size of a single feed. New records are appended to the last chunk; earlier chunks do not change.
- **Lite** feeds for low-capacity devices: records from the last 46 / 90 / 180 / 365 days.
- Every hour only new records are fetched (usually a single API request). Once a week the whole list is fetched again, so records the source has removed drop out of the feeds.
- When a full scan finishes, the number of records seen is compared with the total reported by the API (completeness check). If it falls short, the new data is not used and the existing database and feeds are kept.
- The UI shows whether an address has ever appeared in the list, when it was added, the source's description, and **which feed files carry it to the firewall**.

## Architecture

```
                      internet
                         |
                +--------v--------+
                |      sync       |  SGB API -> sgb.db (full history) -> feeds/*.txt (hourly)
                +--------+--------+
                         |  data volume
          +--------------+---------------+
          | (read-only)  |               | (read-only)
 +--------v--------+     |      +--------v--------+
 |       ui        |<----+------+      nginx      |<-- https://SERVER:1818
 | internal, no    |  backend   | TLS, IP, passwd |      /        -> UI (UI_ALLOWED + password)
 | published port  | (internal) +-----------------+      /feed/   -> feed list and files
 +-----------------+                                                (FEED_ALLOWED + UI_ALLOWED)
```

| Service | Role | Exposed |
|---|---|---|
| `sync` | Pulls the list from the SGB API, updates the database and the feeds | No (outbound internet only) |
| `ui` | Status screen and lookup | No (reachable only through nginx) |
| `nginx` | HTTPS, IP restriction, password; serves the UI and the feed files | Yes, a single port |

## Installation

Requirements: `git`, and Docker Engine with the Compose plugin (see Docker's [installation guide for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)). A Linux server or VM is recommended. Tested on a clean Ubuntu Server 24.04 install with Docker Engine 29.10.0 and Compose 5.8.0.

Docker commands need `sudo` unless your user is in the `docker` group (see the post-installation notes in the Docker documentation). The commands below are written without `sudo`.

```bash
git clone https://github.com/k0zzi/sgb-feed.git
cd sgb-feed
cp .env.example .env
nano .env            # or any editor: set UI_PASS, UI_ALLOWED, FEED_ALLOWED and CERT_IP (see below)
docker compose up -d --build
```

The two address settings are easy to mix up:

- `FEED_ALLOWED` is the address of the **firewall** (the client). It is the source address the server sees when the firewall pulls a feed.
- `CERT_IP` is the address of **this server**, the one you put into the firewall's feed URL (for example `https://192.168.2.10:1818/feed/ip-part1.txt` means `CERT_IP=192.168.2.10`). The certificate is generated for this address on first start; if it is wrong or empty, the firewall rejects the certificate.

The first run fetches the whole list, which takes **10-30 minutes** depending on the API speed. To follow the progress:

```bash
docker compose logs -f sync     # "Sayfa 120/336 (ilerleme: %35) ..." (log messages are Turkish)
```

Then:

- **UI:** `https://SERVER_IP:1818`
- **Feed list:** `https://SERVER_IP:1818/feed/` (line count, size and last change time of every file; the same data is available as `/feed/index.json`)

On first start two things are generated in the `certs/` folder, a CA (`ca.crt`, `ca.key`) and a server certificate signed by that CA (`server.crt`, `server.key`) with a subject alternative name (SAN). Browsers show a warning until they trust the CA. Set `CERT_IP` (and, if you use a DNS name, `CERT_CN`) in `.env` **before the first start**: the server certificate is only valid for the names and addresses listed there, so it must contain the address the firewall puts into the feed URL.

To use your own certificate instead, put `server.crt` and `server.key` into `certs/` before the first start (no CA is created then).

To renew the server certificate (it is valid for 825 days) or to change `CERT_CN`/`CERT_IP`, delete `certs/server.crt` and `certs/server.key` and run `docker compose restart nginx`. The existing CA signs the new certificate, so nothing changes on the firewalls.

### Trusting the CA on the firewall

The firewall validates the server certificate when it pulls a feed, so it must trust the CA. Install **`certs/ca.crt`** (the CA certificate only; never `ca.key` or `server.key`) on the firewall:

- **OPNsense:** *System -> Trust -> Authorities -> Add* (method: *Import an existing Certificate Authority*), paste the contents of `ca.crt` (certificate data only; leave the private key empty).

You can check the certificate from any machine that has `ca.crt`:

```bash
curl --cacert ca.crt https://SERVER_IP:1818/feed/index.json
```

With the Windows `curl.exe` this can fail with `schannel: the revocation status is unknown`, because the certificate carries no revocation (CRL/OCSP) address. For the test, add `--ssl-no-revoke`. Without `--cacert` the same request is rejected as an untrusted root, as it should be.

## Feeds

All files are under `https://SERVER_IP:1818/feed/`. Each file is plain text with one record per line; there are no comments, headers or ports.

| File | Content | Example record |
|---|---|---|
| `domain-part1.txt`, `domain-part2.txt`, ... | Full domain history, chunks of 128,000 | `evil.com` |
| `ip-part1.txt` | Full IPv4 history | `203.0.113.7` |
| `ipv6-part1.txt` | Full IPv6 history (usually empty at the moment) | `2001:db8::1` |
| `url-part1.txt` | Records that include a path | `evil.com/login/index.php` |
| `domain-46d.txt`, `domain-90d.txt`, `domain-180d.txt`, `domain-365d.txt` | Lite: domains seen in the last N days | |
| `ip-46d.txt`, `ip-90d.txt`, `ip-180d.txt`, `ip-365d.txt` | Lite: IPv4 addresses seen in the last N days | |

Notes:

- **URL records are not added to the domain list.** A record such as `evil.com/phish` does not block all of `evil.com`; such records are blocked as URLs in the web filter.
- **Chunk addresses are stable.** As the list grows, new chunk files (`domain-part5.txt`, ...) appear. Defining a few empty chunks on the firewall in advance is good practice so you do not forget to add them later; a chunk that does not exist returns 404.
- **Which feed to use?** The full list also contains records from years ago. Old IPs may belong to someone else today and carry a false-positive risk. Prefer the Lite feeds depending on device capacity and risk appetite. The windows can be changed with `FEED_WINDOWS` in `.env`.

## Configuration (`.env`)

| Variable | Description | Default |
|---|---|---|
| `HTTPS_PORT` | Published port | `1818` |
| `UI_USER`, `UI_PASS` | UI login. nginx does not start if `UI_PASS` is empty or left at the example value (`change-me`) | `admin`, - |
| `UI_ALLOWED` | Networks allowed to open the UI, comma separated (they may also pull the feeds) | - (required) |
| `FEED_ALLOWED` | Firewall IPs that pull the feeds, comma separated | - (required) |
| `PAGE_SIZE` | Records fetched per API request | `1500` |
| `PART_SIZE` | Lines per full-list chunk | `128000` |
| `FEED_WINDOWS` | Lite feed windows (days) | `46,90,180,365` |
| `FULL_RESYNC_DAYS` | Re-fetch the whole list every N days (0: disabled) | `7` |
| `SYNC_INTERVAL_MINUTES` | Update interval (minutes) | `60` |
| `HEALTH_MAX_AGE_MINUTES` | `sync` becomes "unhealthy" if the last successful sync is older than this | `150` |
| `COMPLETENESS_RATIO` | Minimum share of the reported records a full scan must see (completeness check) | `0.99` |
| `CERT_CN` | Common name and DNS name (SAN) of the generated server certificate | `sgb-feed` |
| `CERT_IP` | Comma-separated IP addresses (SAN) the firewall uses to reach the server; set it to the address in the feed URL | empty |
| `TZ` | Time zone of the containers: log times and the day boundaries of the Lite windows | `Europe/Istanbul` |
| `HTTPS_PROXY` | Corporate proxy, if one is required | - |
| `NO_PROXY` | Hosts that bypass the proxy | - |
| `STALE_AFTER_HOURS` | The UI shows the data as stale when the last sync is older than this (hours) | `2.5` |

**Allowlist:** addresses in `config/allowlist.txt` are never written to any feed. Domain entries also cover their subdomains. Changes show up in the feeds at the next sync.

## Connecting a firewall

### OPNsense

- **IP feeds:** a **URL Table (IPs)** alias under *Firewall -> Aliases*. If capacity is not enough, raise *Firewall -> Settings -> Advanced -> Firewall Maximum Table Entries*.
- **Domain feeds:** *Services -> Unbound DNS -> Blocklist*. Add one entry per file (`domain-part1.txt` ... `domain-partN.txt`) with its full feed URL, leave *Type of DNSBL*, *Wildcard Domains* and *Source Net(s)* empty, then **Apply**. The list page shows each address under *URLs of Blocklists*. Entries match the exact name only (no subdomains) unless you fill *Wildcard Domains*.
- **Checking the DNS blocklist:** `configctl unbound dnsbl` prints `OK` even when nothing was downloaded, so check two things instead: `docker compose logs nginx` must show the firewall fetching each `domain-partN.txt` with status 200, and *Services -> Unbound DNS -> Blocklist -> Tester* must answer `Block` for a listed name (take one from `domain-part1.txt`). From a client that uses the firewall's resolver, the blocked name resolves to `0.0.0.0`.
- To refresh the blocklists on a schedule, add a cron job *Update Unbound DNSBLs* under *System -> Settings -> Cron*. The feeds change at most hourly.
- The firewall must trust the CA (see "Trusting the CA on the firewall").
- **`FEED_ALLOWED` must be the source address the server actually sees.** A routed firewall usually connects from its interface address in the server's network (for example `10.1.30.1`), not from its WAN address. Read it from the nginx log (`docker compose logs nginx`: a pull that was refused shows as `403 ... client: <address>`), put that address into `FEED_ALLOWED` and run `docker compose up -d nginx`.
- **Re-fetching an alias:** after a failed download OPNsense waits for the alias refresh interval before it tries again, and `configctl filter refresh_aliases` skips aliases that are not due. To force a fetch right away, delete the alias cache file and refresh: `rm /var/db/aliastables/ALIAS_NAME.md5.txt && configctl filter refresh_aliases`. Check the result with `pfctl -t ALIAS_NAME -T show | wc -l`.

## Operation

```bash
docker compose ps                 # service state (sync: healthy/unhealthy)
docker compose logs -f sync       # sync log
docker compose logs nginx         # access log, setup errors
git pull && docker compose up -d --build              # update
```

- The health state of `sync` looks at the age of the last successful sync. Your monitoring system (PRTG, Zabbix, etc.) can read the output of `docker compose ps`, the `/api/status` JSON of the UI, or `/feed/index.json`.
- `last_success` is the time the sync run finished building the feeds (not the time the run started), so it matches the file times in `/feed/`.
- The UI audit log (who looked up what, and when) is kept in the `ui-logs` volume.
- The database and the feeds live in the `data` volume (about 143 MB at the time of writing). If it is deleted, the next run fetches the whole list again.

## Security notes

- The UI is read-only; nginx allows GET requests only.
- The `ui` service sits on an internal network without internet access and publishes no port. It mounts the data read-only.
- Under `/feed/` only feed files whose name matches a fixed pattern are served. The database, the status file and the logs are never exposed.
- The password is kept as a hash in nginx and is not forwarded to the UI.
- `certs/ca.key` signs the server certificate. Keep it on this server only and never copy it to a firewall; only `ca.crt` is distributed. Back it up if you want to renew the server certificate later without touching the firewalls.
- Access control lives in nginx (`UI_ALLOWED`, `FEED_ALLOWED`), not in the host firewall: Docker publishes the port through its own firewall rules, so host firewall tools such as `ufw` do not filter it (Docker documentation, "Packet filtering and firewalls"). Set `HTTPS_PORT` and your network design with that in mind.
- Containers run as a non-root user (nginx workers run as the `nginx` user).
- The Python services use the standard library only; no Python packages are downloaded.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `nginx` does not start | Look for an `[sgb-setup] ERROR` line in `docker compose logs nginx` (password, invalid network value). |
| 403 even from an allowed network | `FEED_ALLOWED` or `UI_ALLOWED` does not contain the address nginx sees. Read the address from the `client:` field of the error line in `docker compose logs nginx`, correct `.env` and run `docker compose up -d nginx`. A firewall usually connects from its interface address toward the server, not from its WAN address. |
| `sync` unhealthy | Look for the `Bitti:` line in `docker compose logs sync` (connection, proxy, API error). |
| The UI says "Veritabanı şu an okunamıyor" (database cannot be read right now) | `sync` was killed during a write. It fixes itself when `sync` restarts. |
| Log line `Tam tarama eksik: API ... kayıt bildiriyor, yalnızca ... kayıt görüldü` (full scan incomplete) | The scan finished without reaching the end of the list: too many pages were skipped (see the next row), or the API's paging behavior may have changed. Existing data is kept and the next run tries again. If it keeps repeating, check the API behavior. |
| Log lines with `ATLANDI` (skipped), or the UI reports skipped pages after the last full scan | The API returned these pages empty 3 times in a row. The scan was accepted because it still passed the completeness check, but the records of those pages are missing until the next full scan (`FULL_RESYNC_DAYS`). The `WARNING` lines show what the API reported for each attempt. |
| The firewall reports a certificate error when pulling a feed | Either the firewall does not trust `ca.crt` (see "Trusting the CA on the firewall"), or the address in the feed URL is not in the certificate (`CERT_IP`/`CERT_CN`). Check with `openssl x509 -in certs/server.crt -noout -ext subjectAltName`, then delete `certs/server.crt` and `certs/server.key` and restart nginx. |

## Development

The tests cover full and incremental scans against a fake API, chunk stability, the Lite windows, the allowlist, failure cases and the UI:

```bash
pip install pytest
pytest sync ui
```

## Source

Data: [SGB](https://siberguvenlik.gov.tr). This project is unofficial.

## License

The code is released under the [MIT License](LICENSE). The data it downloads comes from SGB and is subject to SGB's own terms of use; this license does not cover it.
