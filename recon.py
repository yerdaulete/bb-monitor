#!/usr/bin/env python3
"""
recon.py — watch LIVE assets under your in-scope wildcards and alert on new
subdomains / hosts via Telegram.

Pipeline per run (per root in scope.txt):
  subfinder (passive subdomains) -> dnsx (keep resolving + grab CNAME)
  -> httpx (probe web hosts for status/title/tech) -> diff vs state -> alert.

This one actually touches the targets (DNS + HTTP), so it only ever enumerates
roots YOU list in scope.txt. Keep that file to authorized, in-scope wildcards.

First run saves a baseline and sends one summary line (no per-host spam).
After that you only get NEW hosts.

Requires on PATH: subfinder, dnsx, httpx  (installed by the workflow).

Env:
  TELEGRAM_BOT_TOKEN  (required)
  TELEGRAM_CHAT_ID    (required)
  SCOPE_FILE          default scope.txt
  STATE_FILE          default state/recon.json
  MAX_MSGS            default 50
  HTTPX_RATELIMIT     default 50     (requests/sec cap for httpx)
  DRY_RUN             "1" -> print instead of send
  PING                "1" -> send connectivity test and exit
"""

import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

SCOPE_FILE = os.environ.get("SCOPE_FILE", "scope.txt")
STATE_FILE = os.environ.get("STATE_FILE", "state/recon.json")
MAX_MSGS = int(os.environ.get("MAX_MSGS", "50"))
HTTPX_RL = os.environ.get("HTTPX_RATELIMIT", "50")
DRY_RUN = os.environ.get("DRY_RUN", "") in ("1", "true", "yes")
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")


# ------------------------------------------------------------------- tool runner
def need(tool):
    if not shutil.which(tool):
        sys.exit(f"'{tool}' not found on PATH (the workflow installs it; "
                 f"locally: go install github.com/projectdiscovery/{tool}/...@latest)")


def run(cmd, timeout=900):
    """Run a command, return stdout (str). Never raises on non-zero exit."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0 and p.stderr.strip():
            print(f"[warn] {cmd[0]} rc={p.returncode}: {p.stderr.strip()[:200]}")
        return p.stdout
    except subprocess.TimeoutExpired:
        print(f"[warn] {cmd[0]} timed out after {timeout}s")
        return ""
    except Exception as e:
        print(f"[warn] {cmd[0]} failed: {e}")
        return ""


def _tmp(lines):
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.write("\n".join(lines))
    f.close()
    return f.name


# ----------------------------------------------------------------- recon stages
def enum_subdomains(root):
    out = run(["subfinder", "-d", root, "-silent"], timeout=300)
    subs = {root}
    for line in out.splitlines():
        h = line.strip().lower().rstrip(".")
        if h and (h == root or h.endswith("." + root)):
            subs.add(h)
    return subs


def resolve(hosts):
    """dnsx: keep only resolving hosts, capture A + CNAME."""
    if not hosts:
        return {}
    path = _tmp(sorted(hosts))
    out = run(["dnsx", "-l", path, "-silent", "-json", "-a", "-cname"], timeout=600)
    os.unlink(path)
    res = {}
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        h = (d.get("host") or "").lower().rstrip(".")
        if not h:
            continue
        res[h] = {
            "a": d.get("a") or [],
            "cname": [c.lower().rstrip(".") for c in (d.get("cname") or [])],
        }
    return res


def probe(hosts):
    """httpx: web metadata for hosts that serve HTTP(S)."""
    if not hosts:
        return {}
    path = _tmp(sorted(hosts))
    out = run(["httpx", "-l", path, "-silent", "-json", "-no-color",
               "-title", "-tech-detect", "-status-code",
               "-timeout", "10", "-rl", HTTPX_RL], timeout=900)
    os.unlink(path)
    info = {}
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        h = (d.get("input") or d.get("host") or "").lower().rstrip(".")
        if not h:
            # derive from url as a fallback
            u = d.get("url", "")
            h = u.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower()
        if not h:
            continue
        tech = d.get("tech") or d.get("technologies") or []
        info[h] = {
            "status": d.get("status_code") or d.get("status-code"),
            "title": (d.get("title") or "")[:120],
            "tech": tech if isinstance(tech, list) else [tech],
            "webserver": d.get("webserver") or "",
            "url": d.get("url") or "",
        }
    return info


def match_root(host, roots):
    best = ""
    for r in roots:
        if host == r or host.endswith("." + r):
            if len(r) > len(best):
                best = r
    return best


def build_current(roots):
    candidates = set()
    for r in roots:
        subs = enum_subdomains(r)
        print(f"[subfinder] {r}: {len(subs)} candidates")
        candidates |= subs

    resolved = resolve(candidates)
    print(f"[dnsx] {len(resolved)}/{len(candidates)} resolve")

    http = probe(set(resolved))
    print(f"[httpx] {len(http)} serve HTTP")

    hosts = {}
    for h, dns in resolved.items():
        hi = http.get(h, {})
        hosts[h] = {
            "root": match_root(h, roots),
            "a": dns["a"],
            "cname": dns["cname"],
            "status": hi.get("status"),
            "title": hi.get("title", ""),
            "tech": hi.get("tech", []),
            "webserver": hi.get("webserver", ""),
            "url": hi.get("url", ""),
        }
    return hosts


# ------------------------------------------------------------------------ diff
def diff(prev, cur):
    new_hosts = [h for h in cur if h not in prev]
    # takeover-interesting first (has CNAME), then alphabetical
    new_hosts.sort(key=lambda h: (not cur[h]["cname"], h))
    return new_hosts


# -------------------------------------------------------------------- messages
def esc(s):
    return html.escape(str(s), quote=False)


def format_host(h, info):
    lines = ["<b>\U0001F195 NEW SUBDOMAIN</b>", f"<code>{esc(h)}</code>"]
    if info["root"]:
        lines.append(f"root: {esc(info['root'])}")

    if info["status"] is not None:
        bits = [f"HTTP {info['status']}"]
        if info["title"]:
            bits.append(f'"{esc(info["title"])}"')
        if info["webserver"]:
            bits.append(esc(info["webserver"]))
        lines.append("\u21B3 " + " \u00b7 ".join(bits))
        if info["tech"]:
            lines.append("tech: " + esc(", ".join(info["tech"])))
    else:
        a = ", ".join(info["a"][:3]) if info["a"] else "—"
        lines.append(f"\u21B3 resolves: {esc(a)} (no HTTP)")

    if info["cname"]:
        # CNAME shown always — dangling CNAME = takeover signal worth an eye
        lines.append("CNAME: " + esc(", ".join(info["cname"][:3])))

    url = info["url"] or f"https://{h}"
    lines.append(f"\U0001F517 {esc(url)}")
    return "\n".join(lines)


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
    print("[tg] gave up on one message")


# ----------------------------------------------------------------------- state
def read_scope(path):
    roots = []
    try:
        for line in open(path):
            line = line.split("#", 1)[0].strip().lower()
            if not line:
                continue
            if line.startswith("*."):
                line = line[2:]
            line = line.lstrip(".").rstrip(".")
            if line:
                roots.append(line)
    except FileNotFoundError:
        pass
    return sorted(set(roots))


def load_state():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
            return d.get("hosts", {}) if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[state] unreadable ({e}); treating as empty")
        return {}


def save_state(hosts):
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"hosts": hosts, "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
                  f, ensure_ascii=False, sort_keys=True, indent=0)


# ------------------------------------------------------------------------ main
def main():
    if not TOKEN or not CHAT:
        sys.exit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")

    if os.environ.get("PING", "") in ("1", "true", "yes"):
        tg_send("\u2705 recon-monitor connected.")
        print("ping sent")
        return

    for t in ("subfinder", "dnsx", "httpx"):
        need(t)

    roots = read_scope(SCOPE_FILE)
    if not roots:
        print(f"[scope] {SCOPE_FILE} has no roots yet — add in-scope wildcards, one per line. "
              f"Nothing to do.")
        return
    print(f"[scope] {len(roots)} root(s): {', '.join(roots)}")

    prev = load_state()
    cur = build_current(roots)

    if not cur:
        sys.exit("No hosts resolved from any root; aborting without touching state")

    if not prev:
        save_state(cur)
        tg_send("\u2705 <b>recon-monitor baseline set</b>\n"
                f"Tracking <b>{len(cur)}</b> live hosts across {len(roots)} root(s).\n"
                "You'll get alerts on new subdomains/hosts from here on.")
        print(f"[baseline] saved {len(cur)} hosts")
        return

    new_hosts = diff(prev, cur)
    print(f"[diff] {len(new_hosts)} new host(s)")

    sent = 0
    for h in new_hosts:
        if sent >= MAX_MSGS:
            tg_send(f"\u2795 +{len(new_hosts) - sent} more new hosts this run "
                    f"(raise MAX_MSGS).")
            break
        tg_send(format_host(h, cur[h]))
        sent += 1
        time.sleep(1)

    save_state(cur)
    print(f"[state] saved {len(cur)} hosts")


if __name__ == "__main__":
    main()
