#!/usr/bin/env python3
"""
scopebot.py — manage recon scope.txt from Telegram, so you never edit the file by hand.

A scheduled workflow runs this; it polls getUpdates and processes commands sent to the
bot BY YOU (your chat id only — everyone else is ignored):

  /add d1.com *.d2.com   add one or more roots
  /remove d.com          remove a root
  /list   (or /scope)    reply with the current scope
  /help                  usage
  <a bare domain>        same as /add

Changed scope.txt + the update offset are committed back by the workflow.

Safety: this only edits the list of roots the recon scanner is allowed to touch. YOU still
decide what goes in — nothing is auto-pulled from any program list. Add only authorized,
in-scope wildcards.

Env:
  TELEGRAM_BOT_TOKEN  (required)
  TELEGRAM_CHAT_ID    (required)  only this chat may command the bot
  SCOPE_FILE          default scope.txt
  OFFSET_FILE         default state/tg_offset.json
  DRY_RUN             "1" -> print replies instead of sending
  UPDATES_FIXTURE     test hook: path to a JSON file of updates (skips the live poll)
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

SCOPE_FILE = os.environ.get("SCOPE_FILE", "scope.txt")
OFFSET_FILE = os.environ.get("OFFSET_FILE", "state/tg_offset.json")
DRY_RUN = os.environ.get("DRY_RUN", "") in ("1", "true", "yes")
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


# ------------------------------------------------------------------- telegram io
def tg_api(method, params=None):
    url = f"https://api.telegram.org/bot{TOKEN}/{method}"
    data = json.dumps(params or {}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.loads(r.read())


def send(text):
    if DRY_RUN:
        print("\n----- REPLY (dry-run) -----\n" + text)
        return
    try:
        tg_api("sendMessage", {"chat_id": CHAT, "text": text, "parse_mode": "HTML",
                               "disable_web_page_preview": True})
    except Exception as e:
        print(f"[tg] send error: {e}")


def get_updates(offset):
    if os.environ.get("UPDATES_FIXTURE"):
        return json.load(open(os.environ["UPDATES_FIXTURE"]))
    try:
        r = tg_api("getUpdates", {"offset": offset, "timeout": 0,
                                  "allowed_updates": ["message"]})
        return r.get("result", []) if r.get("ok") else []
    except Exception as e:
        print(f"[tg] getUpdates error: {e}")
        return []


# ---------------------------------------------------------------------- scope io
def normalize(tok):
    tok = tok.strip().lower()
    tok = re.sub(r"^[a-z]+://", "", tok)      # scheme
    tok = tok.split("/", 1)[0]                # path
    tok = tok.split(":", 1)[0]                # port
    if tok.startswith("*."):
        tok = tok[2:]
    tok = tok.strip(".")
    return tok if DOMAIN_RE.match(tok) else None


def read_scope_lines():
    try:
        return open(SCOPE_FILE).read().splitlines()
    except FileNotFoundError:
        return []


def parse_roots(lines):
    roots = []
    for ln in lines:
        s = ln.split("#", 1)[0].strip().lower()
        if s.startswith("*."):
            s = s[2:]
        s = s.strip(".")
        if s:
            roots.append(s)
    return roots


def write_scope(header, roots):
    body = "\n".join(header).rstrip("\n")
    out = (body + "\n\n" if body else "") + "\n".join(sorted(set(roots)))
    with open(SCOPE_FILE, "w") as f:
        f.write(out + "\n")


def leading_comments(lines):
    head = []
    for ln in lines:
        if ln.split("#", 1)[0].strip() == "":   # comment or blank
            head.append(ln)
        else:
            break
    return head


# ------------------------------------------------------------------- offset io
def load_offset():
    try:
        return int(json.load(open(OFFSET_FILE)).get("offset", 0))
    except Exception:
        return 0


def save_offset(n):
    os.makedirs(os.path.dirname(OFFSET_FILE) or ".", exist_ok=True)
    json.dump({"offset": n}, open(OFFSET_FILE, "w"))


# ------------------------------------------------------------------- command handling
HELP = ("<b>scope manager</b>\n"
        "/add d1.com *.d2.com — add roots\n"
        "/remove d.com — remove a root\n"
        "/list — show current scope\n"
        "or just send a domain to add it\n\n"
        "Only authorized, in-scope wildcards. The scanner touches only what's listed here.")


def handle(text, roots):
    """Return (reply, changed) given a command and the mutable roots set."""
    parts = text.split()
    cmd = parts[0].lower()
    args = parts[1:]

    is_bare = not cmd.startswith("/")
    if cmd == "/add" or is_bare:
        toks = parts if is_bare else args
        if not toks:
            return "Usage: /add domain.com", False
        norm = [(t, normalize(t)) for t in toks]
        # Bare chatter: if ANY token isn't a clean domain, treat the whole message
        # as conversation and ignore it silently (don't add, don't warn).
        if is_bare and any(d is None for _, d in norm):
            return None, False
        added, bad, dup = [], [], []
        for t, d in norm:
            if not d:
                bad.append(t)
            elif d in roots:
                dup.append(d)
            else:
                roots.add(d)
                added.append(d)
        msg = []
        if added:
            msg.append("\u2795 added: " + ", ".join(added))
        if dup:
            msg.append("already in scope: " + ", ".join(dup))
        if bad:
            msg.append("\u26A0 not a domain: " + ", ".join(bad))
        if not msg:
            return None, False
        msg.append(f"scope now: {len(roots)}")
        return "\n".join(msg), bool(added)

    if cmd == "/remove":
        if not args:
            return "Usage: /remove domain.com", False
        removed, miss = [], []
        for t in args:
            d = normalize(t) or t.strip().lower().lstrip("*.").strip(".")
            if d in roots:
                roots.discard(d)
                removed.append(d)
            else:
                miss.append(d)
        msg = []
        if removed:
            msg.append("\u2796 removed: " + ", ".join(removed))
        if miss:
            msg.append("not in scope: " + ", ".join(miss))
        msg.append(f"scope now: {len(roots)}")
        return "\n".join(msg), bool(removed)

    if cmd in ("/list", "/scope"):
        if roots:
            return f"\U0001F4CB scope ({len(roots)}):\n" + "\n".join(sorted(roots)), False
        return "\U0001F4CB scope is empty — /add a domain to start.", False

    if cmd in ("/help", "/start"):
        return HELP, False

    return None, False   # unknown non-command chatter -> ignore silently


# ------------------------------------------------------------------------ main
def main():
    if not TOKEN or not CHAT:
        sys.exit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")

    lines = read_scope_lines()
    header = leading_comments(lines)
    roots = set(parse_roots(lines))

    offset = load_offset()
    updates = get_updates(offset + 1 if offset else 0)
    print(f"[tg] {len(updates)} update(s)")

    changed = False
    max_id = offset
    for u in updates:
        max_id = max(max_id, u.get("update_id", 0))
        msg = u.get("message") or u.get("edited_message")
        if not msg:
            continue
        if str(msg.get("chat", {}).get("id")) != str(CHAT):
            print(f"[skip] foreign chat {msg.get('chat', {}).get('id')}")
            continue
        text = (msg.get("text") or "").strip()
        if not text:
            continue
        reply, did = handle(text, roots)
        if did:
            changed = True
        if reply:
            send(reply)

    if changed:
        write_scope(header, roots)
        print(f"[scope] updated -> {len(roots)} roots")
    if max_id != offset:
        save_offset(max_id)
        print(f"[offset] -> {max_id}")


if __name__ == "__main__":
    main()
