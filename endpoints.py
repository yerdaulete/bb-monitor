#!/usr/bin/env python3
"""
endpoints.py — watch for NEW API/web endpoints on recon's live hosts. #4 in the plan.
This is where your IDOR/BOLA live: a new endpoint isn't a bug by itself, it's a fresh
place to point your hands. This module finds it; you still do the actual testing.

Pipeline per live host (from state/recon.json, which `git pull` refreshes from GitHub):
  katana (crawl, follows JS too) -> collect discovered URLs
  + for each distinct .js file found: jsluice urls (deep JS endpoint extraction) -- OPTIONAL,
    skipped gracefully if the `jsluice` binary isn't installed, katana alone still works.
  -> normalize (collapse numeric/UUID/hex path segments to {id}, keep query PARAM NAMES
     only — not values, so /users/1 and /users/2 are the same endpoint, not two "new" ones)
  -> diff vs local state -> alert on new normalized endpoints.

New endpoints whose normalized path/params look ID-shaped get a ⭐ flag — purely a text
match on the discovered path, zero extra requests, zero risk. It's a priority hint, not a
finding: still your call whether it's actually an IDOR.

State is LOCAL to this machine (state/endpoints.json) — never committed/pushed back to
git, so this script needs no GitHub credentials, read-only `git pull` is enough.

Requires on PATH: katana (required), jsluice (optional — enhances JS coverage if present).

Env:
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID   (required)
  RECON_FILE    default state/recon.json
  STATE_FILE    default state/endpoints.json
  MAX_MSGS      default 40
  MAX_HOSTS     default 200       (hosts crawled per run; raise as targets grow)
  DEPTH         default 2         (katana crawl depth)
  RATE_LIMIT    default 40        (requests/sec, katana)
  TIMEOUT       default 600       (seconds, per-host katana run)
  DRY_RUN / PING
"""

import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

RECON_FILE = os.environ.get("RECON_FILE", "state/recon.json")
STATE_FILE = os.environ.get("STATE_FILE", "state/endpoints.json")
MAX_MSGS = int(os.environ.get("MAX_MSGS", "40"))
MAX_HOSTS = int(os.environ.get("MAX_HOSTS", "200"))
DEPTH = os.environ.get("DEPTH", "2")
RATE_LIMIT = os.environ.get("RATE_LIMIT", "40")
TIMEOUT = int(os.environ.get("TIMEOUT", "600"))
DRY_RUN = os.environ.get("DRY_RUN", "") in ("1", "true", "yes")
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")

HAS_JSLUICE = shutil.which("jsluice") is not None

ID_SEG = re.compile(r"^\d+$")
UUID_SEG = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_SEG = re.compile(r"^[0-9a-f]{16,}$", re.I)
IDISH_PARAM = re.compile(r"(^|_)(id|uid|uuid|pk|user|account|order|invoice|doc|file)s?($|_)", re.I)


# ----------------------------------------------------------------------- tool runner
def run(cmd, timeout=TIMEOUT, input_text=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=input_text)
        if p.returncode != 0 and p.stderr.strip():
            print(f"[warn] {cmd[0]} rc={p.returncode}: {p.stderr.strip()[:200]}")
        return p.stdout
    except subprocess.TimeoutExpired:
        print(f"[warn] {cmd[0]} timed out after {timeout}s")
        return ""
    except FileNotFoundError:
        print(f"[warn] '{cmd[0]}' not found on PATH")
        return ""
    except Exception as e:
        print(f"[warn] {cmd[0]} failed: {e}")
        return ""


# --------------------------------------------------------------------- normalization
def normalize_path(path):
    """Collapse numeric/UUID/long-hex path segments to {id} so /x/1 and /x/2 are one
    endpoint, not two "new" ones. Returns the normalized path and whether anything
    was collapsed (that's the ID-shape signal)."""
    segs = (path.split("?", 1)[0] or "/").split("/")
    out, collapsed = [], False
    for s in segs:
        if s and (ID_SEG.match(s) or UUID_SEG.match(s) or HEX_SEG.match(s)):
            out.append("{id}")
            collapsed = True
        else:
            out.append(s)
    return "/".join(out) or "/", collapsed


def parse_url(raw):
    try:
        u = urllib.parse.urlsplit(raw.strip())
    except Exception:
        return None
    if not u.scheme or not u.netloc or u.scheme not in ("http", "https"):
        return None
    host = u.netloc.lower().split("@")[-1].split(":")[0]
    npath, collapsed = normalize_path(u.path or "/")
    params = sorted({k for k, _ in urllib.parse.parse_qsl(u.query)})
    idish = collapsed or any(IDISH_PARAM.search(p) for p in params)
    return {"host": host, "path": npath, "params": params, "idish": idish,
            "example": raw.strip()}


def endpoint_key(e):
    p = ",".join(e["params"])
    return f"{e['host']}{e['path']}" + (f"?{p}" if p else "")


# ----------------------------------------------------------------------- crawling
def crawl_host(url):
    """katana crawl -> set of discovered absolute URLs (pages + JS files)."""
    out = run(["katana", "-u", url, "-silent", "-d", DEPTH, "-jc",
               "-fs", "fqdn", "-rl", RATE_LIMIT, "-timeout", "10",
               "-c", "10", "-kf", "robotstxt,sitemapxml"])
    return {ln.strip() for ln in out.splitlines() if ln.strip().startswith("http")}


def js_endpoints(js_urls):
    """Optional deep-JS pass: fetch each JS file, run jsluice urls on it, collect any
    URLs/paths it finds. Skipped entirely if jsluice isn't installed."""
    if not HAS_JSLUICE or not js_urls:
        return set()
    found = set()
    for ju in js_urls:
        try:
            req = urllib.request.Request(ju, headers={"User-Agent": "endpoints-monitor/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read(2_000_000).decode("utf-8", "replace")
        except Exception:
            continue
        out = run(["jsluice", "urls", "-"], timeout=30, input_text=body)
        for ln in out.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
                u = d.get("url") or d.get("URL") or ""
            except Exception:
                u = ln
            if not u:
                continue
            if u.startswith("/"):
                base = urllib.parse.urlsplit(ju)
                u = f"{base.scheme}://{base.netloc}{u}"
            if u.startswith("http"):
                found.add(u)
    return found


def build_current(hosts):
    endpoints = {}
    for n, (host, info) in enumerate(sorted(hosts.items())):
        if n >= MAX_HOSTS:
            print(f"[endpoints] host cap {MAX_HOSTS} reached"); break
        base = info.get("url") or f"https://{host}"
        urls = crawl_host(base)
        js_urls = {u for u in urls if u.split("?", 1)[0].lower().endswith(".js")}
        urls |= js_endpoints(js_urls)
        print(f"[katana] {host}: {len(urls)} url(s)"
              + (f" (+jsluice on {len(js_urls)} js)" if HAS_JSLUICE and js_urls else ""))
        for raw in urls:
            e = parse_url(raw)
            if e:
                endpoints[endpoint_key(e)] = e
        time.sleep(0.5)
    return endpoints


# --------------------------------------------------------------------------- format
def esc(s):
    return html.escape(str(s), quote=False)


def format_endpoint(e):
    star = "\u2B50 " if e["idish"] else ""
    lines = [f"<b>{star}\U0001F195 NEW ENDPOINT</b>",
             f"<code>{esc(e['host'])}{esc(e['path'])}</code>"]
    if e["params"]:
        lines.append("params: " + esc(", ".join(e["params"])))
    if e["idish"]:
        lines.append("\u21B3 looks ID-shaped — worth checking IDOR/BOLA first")
    lines.append(f"\U0001F517 {esc(e['example'])}")
    return "\n".join(lines)


# ----------------------------------------------------------------------- tg / state
def tg_send(text):
    if DRY_RUN:
        print("\n----- TELEGRAM (dry-run) -----\n" + text)
        return
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = json.dumps({"chat_id": CHAT, "text": text, "parse_mode": "HTML",
                          "disable_web_page_preview": True}).encode()
    for _ in range(5):
        try:
            req = urllib.request.Request(url, data=payload,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                r.read()
            return
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if e.code == 429:
                try:
                    wait = json.loads(body)["parameters"]["retry_after"]
                except Exception:
                    wait = 3
                time.sleep(wait + 1)
                continue
            print(f"[tg] HTTP {e.code}: {body}")
            return
        except Exception as e:
            print(f"[tg] error: {e}")
            time.sleep(2)


def load_recon():
    try:
        return json.load(open(RECON_FILE)).get("hosts", {})
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[recon] unreadable: {e}")
        return {}


def load_state():
    try:
        return json.load(open(STATE_FILE)).get("endpoints", {})
    except Exception:
        return {}


def save_state(eps):
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    json.dump({"endpoints": eps,
               "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
              open(STATE_FILE, "w"), ensure_ascii=False, indent=0)


# ------------------------------------------------------------------------ main
def main():
    if not TOKEN or not CHAT:
        sys.exit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")

    if os.environ.get("PING", "") in ("1", "true", "yes"):
        tg_send("\u2705 endpoints-monitor connected.")
        print("ping sent")
        return

    if not shutil.which("katana"):
        sys.exit("'katana' not found on PATH — run vps-setup.sh first")
    if not HAS_JSLUICE:
        print("[info] jsluice not found — continuing with katana-only JS coverage")

    hosts = {h: i for h, i in load_recon().items() if i.get("status") is not None}
    if not hosts:
        print(f"[recon] no web hosts in {RECON_FILE} yet — run recon first. Nothing to do.")
        return
    print(f"[endpoints] {len(hosts)} web host(s) to crawl")

    prev = load_state()
    cur = build_current(hosts)
    if not cur:
        print("[endpoints] 0 endpoints discovered this run — nothing to diff")
        return

    is_baseline = not prev
    new_keys = [k for k in cur if k not in prev] if not is_baseline else list(cur)
    # ID-shaped endpoints first (your priority targets), then alphabetical
    new_keys.sort(key=lambda k: (not cur[k]["idish"], k))
    print(f"[endpoints] {len(cur)} total, {len(new_keys)} new")

    if is_baseline:
        save_state(cur)
        idish = sum(1 for e in cur.values() if e["idish"])
        tg_send("\u2705 <b>endpoints-monitor baseline set</b>\n"
                f"Tracking <b>{len(cur)}</b> endpoints across {len(hosts)} host(s) "
                f"({idish} ID-shaped).\nYou'll get alerts on new endpoints from here on.")
        print(f"[baseline] saved {len(cur)} endpoints")
        return

    sent = 0
    for k in new_keys:
        if sent >= MAX_MSGS:
            tg_send(f"\u2795 +{len(new_keys) - sent} more new endpoints this run "
                    f"(raise MAX_MSGS).")
            break
        tg_send(format_endpoint(cur[k]))
        sent += 1
        time.sleep(1)

    save_state(cur)
    print(f"[state] saved {len(cur)} endpoints")


if __name__ == "__main__":
    main()
