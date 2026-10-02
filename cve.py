#!/usr/bin/env python3
"""
cve.py — fast(ish) response to fresh CVEs on recon's live hosts. #6 in the plan.

nuclei -update-templates, then scan recon's live hosts with a CONSERVATIVE filter —
severity critical/high, -tags cve, and -etags dos,fuzz,intrusive EXCLUDED by default.
That exclusion is deliberate: several nuclei templates are intentionally disruptive
(DoS checks, fuzzers), and most bug bounty programs restrict or ban automated scanners
outright. Default to the quiet set; only widen ETAGS for a program whose policy actually
allows it. Check each program's scope/testing policy before pointing this at it.

There's no special "only brand-new templates" flag here — nuclei just gets its template
set updated and re-scans every run; freshness comes from diffing (host, template-id)
pairs, so a template added/updated since last run surfaces as NEW the moment it matches,
whether the host is old or new. No baseline suppression either: a confirmed CVE match on
the very first run is a real, actionable finding — same philosophy as checks.py, unlike
the "many hosts on day 1" discovery modules (recon/endpoints), where baselining avoids a
flood of non-findings.

State is LOCAL to this machine (state/cve.json) — never committed/pushed to git.

Requires on PATH: nuclei.

Env:
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID   (required)
  RECON_FILE    default state/recon.json
  STATE_FILE    default state/cve.json
  SEVERITY      default critical,high
  TAGS          default cve
  ETAGS         default dos,fuzz,intrusive   (excluded — override only if a program allows it)
  RATE_LIMIT    default 50
  CONCURRENCY   default 15
  MAX_MSGS      default 40
  MAX_HOSTS     default 500
  TIMEOUT       default 1800   (seconds, whole nuclei run)
  SKIP_UPDATE   "1" -> skip -update-templates (faster local testing)
  DRY_RUN / PING
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

RECON_FILE = os.environ.get("RECON_FILE", "state/recon.json")
STATE_FILE = os.environ.get("STATE_FILE", "state/cve.json")
SEVERITY = os.environ.get("SEVERITY", "critical,high")
TAGS = os.environ.get("TAGS", "cve")
ETAGS = os.environ.get("ETAGS", "dos,fuzz,intrusive")
RATE_LIMIT = os.environ.get("RATE_LIMIT", "50")
CONCURRENCY = os.environ.get("CONCURRENCY", "15")
MAX_MSGS = int(os.environ.get("MAX_MSGS", "40"))
MAX_HOSTS = int(os.environ.get("MAX_HOSTS", "500"))
TIMEOUT = int(os.environ.get("TIMEOUT", "1800"))
SKIP_UPDATE = os.environ.get("SKIP_UPDATE", "") in ("1", "true", "yes")
DRY_RUN = os.environ.get("DRY_RUN", "") in ("1", "true", "yes")
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")

SEV_ICON = {"critical": "\U0001F7E3", "high": "\U0001F534",
           "medium": "\U0001F7E1", "low": "\u26AA", "info": "\u2139\uFE0F"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ------------------------------------------------------------------- tool runner
def run(cmd, timeout=TIMEOUT, input_text=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           input=input_text)
        if p.returncode not in (0, 1) and p.stderr.strip():
            # nuclei can exit 1 on "ran fine, found nothing special" in some versions;
            # only warn loudly on anything else.
            print(f"[warn] {cmd[0]} rc={p.returncode}: {p.stderr.strip()[:300]}")
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


def _tmp(lines):
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.write("\n".join(lines))
    f.close()
    return f.name


# ---------------------------------------------------------------------- scanning
def update_templates():
    if SKIP_UPDATE:
        print("[nuclei] template update skipped (SKIP_UPDATE)")
        return
    run(["nuclei", "-update-templates", "-silent"], timeout=300)
    print("[nuclei] templates updated")


def scan(urls):
    if not urls:
        return []
    path = _tmp(urls)
    out = run(["nuclei", "-l", path, "-silent", "-jsonl",
               "-severity", SEVERITY, "-tags", TAGS, "-etags", ETAGS,
               "-rl", RATE_LIMIT, "-c", CONCURRENCY, "-timeout", "10"])
    os.unlink(path)
    matches = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            d = json.loads(ln)
        except Exception:
            continue
        info = d.get("info") or {}
        tid = d.get("template-id") or d.get("templateID") or d.get("template_id") or ""
        host = d.get("host") or d.get("ip") or ""
        if not tid or not host:
            continue
        sev = (info.get("severity") or "unknown").lower()
        matches.append({
            "template_id": tid,
            "name": info.get("name") or tid,
            "severity": sev,
            "host": host,
            "matched_at": d.get("matched-at") or d.get("matched_at") or host,
            "description": (info.get("description") or "")[:200],
        })
    return matches


# ------------------------------------------------------------------------ diff
def key_of(m):
    return f"{m['host']}::{m['template_id']}"


def rank(m):
    return (SEV_ORDER.get(m["severity"], 9), m["host"])


# -------------------------------------------------------------------- format
def esc(s):
    return html.escape(str(s), quote=False)


def format_match(m):
    icon = SEV_ICON.get(m["severity"], "\u26AA")
    lines = [f"<b>{icon} {esc(m['severity'].upper())} \u00b7 {esc(m['name'])}</b>",
             f"<code>{esc(m['template_id'])}</code>"]
    if m["description"]:
        lines.append(esc(m["description"]))
    lines.append(f"\U0001F517 {esc(m['matched_at'])}")
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
        return set(json.load(open(STATE_FILE)).get("matches", []))
    except Exception:
        return set()


def save_state(keys):
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    json.dump({"matches": sorted(keys),
               "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
              open(STATE_FILE, "w"), indent=0)


# ------------------------------------------------------------------------ main
def main():
    if not TOKEN or not CHAT:
        sys.exit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")

    if os.environ.get("PING", "") in ("1", "true", "yes"):
        tg_send("\u2705 cve-monitor connected.")
        print("ping sent")
        return

    if not shutil.which("nuclei"):
        sys.exit("'nuclei' not found on PATH — run vps-setup.sh first")

    hosts = load_recon()
    urls = [i.get("url") or f"https://{h}" for h, i in hosts.items()
           if i.get("status") is not None][:MAX_HOSTS]
    if not urls:
        print(f"[recon] no web hosts in {RECON_FILE} yet — run recon first. Nothing to do.")
        return
    print(f"[cve] scanning {len(urls)} host(s) · severity={SEVERITY} tags={TAGS} "
          f"etags={ETAGS}")

    update_templates()
    matches = scan(urls)
    matches.sort(key=rank)
    print(f"[cve] {len(matches)} match(es)")

    seen = load_state()
    new = [m for m in matches if key_of(m) not in seen]
    print(f"[cve] {len(new)} new")

    sent = 0
    for m in new:
        if sent >= MAX_MSGS:
            tg_send(f"\u2795 +{len(new) - sent} more new findings this run (raise MAX_MSGS).")
            break
        tg_send(format_match(m))
        sent += 1
        time.sleep(1)

    if new:
        save_state(seen | {key_of(m) for m in new})
        print(f"[state] +{len(new)} matches recorded")


if __name__ == "__main__":
    main()
