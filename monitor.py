#!/usr/bin/env python3
"""
bb-monitor — watch bug bounty programs for NEW programs and SCOPE changes,
push instant alerts to Telegram.

Data source: github.com/arkadiyt/bounty-targets-data (updated several times/day),
covering HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy.

How it works:
  1. Fetch each platform's scope JSON from the raw GitHub mirror.
  2. Normalize into {program_key: {name, url, pays, payout, scope[]}}.
  3. Diff against state/state.json saved from the previous run.
  4. For every changed program send ONE Telegram message:
        - new program
        - new in-scope assets added
        - program flipped VDP -> paying
  5. Save the new state (the workflow commits it back to the repo).

First run has no prior state -> it saves a baseline and sends a single
summary line instead of spamming every program.

Env vars:
  TELEGRAM_BOT_TOKEN   (required)  token from @BotFather
  TELEGRAM_CHAT_ID     (required)  your chat/user id
  ONLY_PAYING          (opt)  "true" -> ignore VDP/no-bounty events        default false
  MAX_MSGS             (opt)  cap messages per run, overflow summarized     default 40
  SCOPE_PER_MSG        (opt)  max assets listed per program message         default 15
  KEYWORDS             (opt)  comma list; if set, only programs whose name
                              contains one of them trigger alerts           default off
  DRY_RUN              (opt)  "1" -> print messages instead of sending      default off
  PING                 (opt)  "1" -> send a connectivity test and exit      default off
  STATE_FILE           (opt)  path to state json           default state/state.json
"""

import html
import json
import os
import sys
import time
import urllib.request
import urllib.error

RAW_BASE = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/"
PLATFORMS = {
    "hackerone": "hackerone_data.json",
    "bugcrowd": "bugcrowd_data.json",
    "intigriti": "intigriti_data.json",
    "yeswehack": "yeswehack_data.json",
    "federacy": "federacy_data.json",
}

STATE_FILE = os.environ.get("STATE_FILE", "state/state.json")
ONLY_PAYING = os.environ.get("ONLY_PAYING", "false").lower() in ("1", "true", "yes")
MAX_MSGS = int(os.environ.get("MAX_MSGS", "40"))
SCOPE_PER_MSG = int(os.environ.get("SCOPE_PER_MSG", "15"))
DRY_RUN = os.environ.get("DRY_RUN", "") in ("1", "true", "yes")
KEYWORDS = [k.strip().lower() for k in os.environ.get("KEYWORDS", "").split(",") if k.strip()]

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")


# ----------------------------------------------------------------------------- fetch
def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "bb-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_json(fname):
    return json.loads(http_get(RAW_BASE + fname))


# ------------------------------------------------------------------- normalization
def _scope(items, ident_keys, type_key):
    """Turn a list of in_scope dicts into a sorted list of 'type::identifier'."""
    out = set()
    for it in items or []:
        if not isinstance(it, dict):
            continue
        ident = None
        for k in ident_keys:
            v = it.get(k)
            if v:
                ident = str(v).strip()
                break
        if not ident:
            continue
        typ = str(it.get(type_key, "") or "").strip().lower() or "?"
        out.add(f"{typ}::{ident}")
    return sorted(out)


def norm_hackerone(p):
    return {
        "platform": "hackerone",
        "name": p.get("name") or p.get("handle") or "?",
        "url": p.get("url") or "",
        "pays": bool(p.get("offers_bounties")),
        "payout": "",  # H1 mirror carries no max-payout number
        "scope": _scope(p.get("targets", {}).get("in_scope"), ("asset_identifier",), "asset_type"),
    }, f"hackerone:{p.get('handle')}"


def norm_bugcrowd(p):
    mp = p.get("max_payout") or 0
    return {
        "platform": "bugcrowd",
        "name": (p.get("name") or "?").strip(),
        "url": p.get("url") or "",
        "pays": bool(mp and mp > 0),
        "payout": f"${mp:,}" if mp else "",
        "scope": _scope(p.get("targets", {}).get("in_scope"), ("target", "uri"), "type"),
    }, f"bugcrowd:{p.get('url')}"


def norm_intigriti(p):
    mb = p.get("max_bounty") or {}
    val, cur = mb.get("value", 0) or 0, mb.get("currency", "") or ""
    return {
        "platform": "intigriti",
        "name": p.get("name") or "?",
        "url": p.get("url") or "",
        "pays": bool(val and val > 0),
        "payout": f"{val:,} {cur}".strip() if val else "",
        "scope": _scope(p.get("targets", {}).get("in_scope"), ("endpoint",), "type"),
    }, f"intigriti:{p.get('id')}"


def norm_yeswehack(p):
    if not p.get("public") or p.get("disabled"):
        return None, None
    mb = p.get("max_bounty", 0) or 0
    pid = p.get("id")
    return {
        "platform": "yeswehack",
        "name": p.get("name") or pid or "?",
        "url": f"https://yeswehack.com/programs/{pid}",
        "pays": bool(mb and mb > 0),
        "payout": f"\u20ac{mb:,}" if mb else "",  # YWH bounties are EUR
        "scope": _scope(p.get("targets", {}).get("in_scope"), ("target",), "type"),
    }, f"yeswehack:{pid}"


def norm_federacy(p):
    return {
        "platform": "federacy",
        "name": p.get("name") or "?",
        "url": p.get("url") or "",
        "pays": bool(p.get("offers_awards")),
        "payout": "",
        "scope": _scope(p.get("targets", {}).get("in_scope"), ("target",), "type"),
    }, f"federacy:{p.get('id')}"


NORMALIZERS = {
    "hackerone": norm_hackerone,
    "bugcrowd": norm_bugcrowd,
    "intigriti": norm_intigriti,
    "yeswehack": norm_yeswehack,
    "federacy": norm_federacy,
}


def build_current(prev):
    """Fetch + normalize every platform. On a platform fetch failure, carry that
    platform's previous entries over unchanged so we never emit false new/removed."""
    cur = {}
    failed = []
    for plat, fname in PLATFORMS.items():
        try:
            raw = fetch_json(fname)
            norm = NORMALIZERS[plat]
            n = 0
            for p in raw:
                entry, key = norm(p)
                if key and entry:
                    cur[key] = entry
                    n += 1
            print(f"[fetch] {plat}: {n} programs")
        except Exception as e:
            failed.append(plat)
            print(f"[fetch] {plat}: FAILED ({e}) -> carrying previous state")
            for k, v in prev.items():
                if v.get("platform") == plat:
                    cur[k] = v
    return cur, failed


# ------------------------------------------------------------------------- diffing
def diff(prev, cur):
    events = []  # (key, entry, kinds:set, new_scopes:list)
    for key, c in cur.items():
        if KEYWORDS and not any(k in c["name"].lower() for k in KEYWORDS):
            continue
        p = prev.get(key)
        if p is None:
            events.append((key, c, {"new"}, c["scope"]))
            continue
        kinds, new_scopes = set(), []
        added = sorted(set(c["scope"]) - set(p.get("scope", [])))
        if added:
            kinds.add("scope")
            new_scopes = added
        if c["pays"] and not p.get("pays"):
            kinds.add("pays")
        if kinds:
            events.append((key, c, kinds, new_scopes))
    if ONLY_PAYING:
        events = [e for e in events if e[1]["pays"]]
    # most valuable first: paying before VDP, new before scope-only
    events.sort(key=lambda e: (not e[1]["pays"], "new" not in e[2], e[1]["name"].lower()))
    return events


# ----------------------------------------------------------------------- messages
def esc(s):
    return html.escape(str(s), quote=False)


def extract_wildcard_roots(scope_entries):
    """Pull apex domains that are explicitly WILDCARD-scoped out of a raw scope list —
    the only kind recon.py's subfinder-based enumeration is safe to run against.
    Itemized-only entries (type 'url'/'domain' with no matching wildcard) are left out
    on purpose: enumerating under those would find hosts nobody authorized testing."""
    roots = set()
    for s in scope_entries:
        typ, _, ident = s.partition("::")
        ident = ident.strip()
        is_wild = typ == "wildcard" or ident.startswith("*.") or "://*." in ident
        if not is_wild:
            continue
        d = ident.split("://", 1)[-1]
        if d.startswith("*."):
            d = d[2:]
        d = d.split("/", 1)[0].split(":", 1)[0].rstrip(".").lower()
        # must reduce to a clean apex: no leftover '*' (e.g. Intigriti's "*.foo.*"
        # multi-wildcard), not empty, not a bare IPv4 literal
        if d and "*" not in d and "." in d and not d.replace(".", "").isdigit():
            roots.add(d)
    return sorted(roots)


def format_event(key, c, kinds, new_scopes):
    tags = []
    if "new" in kinds:
        tags.append("\U0001F195 NEW PROGRAM")
    if "scope" in kinds:
        tags.append(f"\U0001F4C8 SCOPE +{len(new_scopes)}")
    if "pays" in kinds:
        tags.append("\U0001F4B0 NOW PAYS")
    header = " \u00b7 ".join(tags)

    if c["pays"]:
        pay = f"\U0001F4B0 up to {c['payout']}" if c["payout"] else "\U0001F4B0 pays bounties"
    else:
        pay = "\U0001F6AB VDP (no bounty)"

    lines = [
        f"<b>{esc(header)}</b>",
        f"{esc(c['name'])}  <i>[{c['platform']}]</i>",
        pay,
    ]
    if c["url"]:
        lines.append(f"\U0001F517 {esc(c['url'])}")

    show = new_scopes if "scope" in kinds else (c["scope"] if "new" in kinds else [])
    label = "New assets:" if "scope" in kinds else "Scope:"
    if show:
        lines.append(esc(label))
        for s in show[:SCOPE_PER_MSG]:
            typ, _, ident = s.partition("::")
            lines.append(f" \u2022 <code>{esc(ident)}</code> <i>{esc(typ)}</i>")
        if len(show) > SCOPE_PER_MSG:
            lines.append(f" \u2026 +{len(show) - SCOPE_PER_MSG} more")
        roots = extract_wildcard_roots(show)
        if roots:
            lines.append("")
            lines.append("\U0001F4A1 wildcard-safe \u2014 opt in with:")
            lines.append(f"<code>/add {esc(' '.join(roots))}</code>")
    return "\n".join(lines)


def tg_send(text):
    if DRY_RUN:
        print("\n----- TELEGRAM (dry-run) -----\n" + text)
        return
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": CHAT,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode()
    for attempt in range(5):
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
                print(f"[tg] 429, sleeping {wait}s")
                time.sleep(wait + 1)
                continue
            print(f"[tg] HTTP {e.code}: {body}")
            return
        except Exception as e:
            print(f"[tg] error: {e}")
            time.sleep(2)
    print("[tg] giving up on one message")


# -------------------------------------------------------------------------- state
def load_state():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[state] unreadable ({e}), treating as empty")
        return {}


def save_state(cur):
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(cur, f, ensure_ascii=False, sort_keys=True, indent=0)


# --------------------------------------------------------------------------- main
def main():
    if not TOKEN or not CHAT:
        sys.exit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")

    if os.environ.get("PING", "") in ("1", "true", "yes"):
        tg_send("\u2705 bb-monitor connected.")
        print("ping sent")
        return

    prev = load_state()
    cur, failed = build_current(prev)

    if not cur:
        sys.exit("No data fetched from any platform; aborting without touching state")

    is_baseline = len(prev) == 0
    if is_baseline:
        save_state(cur)
        paying = sum(1 for v in cur.values() if v["pays"])
        tg_send(
            "\u2705 <b>bb-monitor baseline set</b>\n"
            f"Tracking <b>{len(cur)}</b> programs across {len(PLATFORMS)} platforms "
            f"({paying} paying).\nYou'll get alerts on new programs and scope changes from here on."
        )
        print(f"[baseline] saved {len(cur)} programs")
        return

    events = diff(prev, cur)
    print(f"[diff] {len(events)} changed programs"
          + (f" (platforms skipped: {', '.join(failed)})" if failed else ""))

    sent = 0
    for key, c, kinds, new_scopes in events:
        if sent >= MAX_MSGS:
            tg_send(f"\u2795 +{len(events) - sent} more changes this run "
                    f"(raise MAX_MSGS to see them).")
            break
        tg_send(format_event(key, c, kinds, new_scopes))
        sent += 1
        time.sleep(1)  # stay well under Telegram rate limits

    # Only persist when every platform fetched cleanly, so a partial outage
    # can't silently bake missing programs into the baseline.
    if failed:
        print(f"[state] NOT saved: {len(failed)} platform(s) failed this run")
    else:
        save_state(cur)
        print(f"[state] saved {len(cur)} programs")


if __name__ == "__main__":
    main()
