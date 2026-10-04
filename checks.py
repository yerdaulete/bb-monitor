#!/usr/bin/env python3
"""
checks.py — high-confidence active checks on the hosts recon already discovered.
Two things, both close to "found -> almost reportable":

  TAKEOVER (#5): hosts with a dangling CNAME, matched against takeover fingerprints.
                 🔴 confirmed = provider CNAME + the service's error-page signature.
                 🟡 possible  = provider CNAME + a dead status (403/404/503) but no sig.
  LEAK (#7):     exposed /.git, /.env, AWS creds — strict content validation + a
                 soft-404 guard so a catch-all 200 page doesn't trigger false hits.

Input: state/recon.json (recon's host inventory). Run recon first.
Output: one Telegram message per NEW finding. No baseline suppression — a live leak or
takeover on run #1 is a real finding, you want it now. Each finding alerts once.

These are signals at high confidence, not proof. You still verify and claim: a key may be
revoked, a takeover still has to be demonstrated. This narrows the field; it doesn't report.

Env:
  TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID  (required)
  RECON_FILE   default state/recon.json
  STATE_FILE   default state/checks.json
  MAX_MSGS     default 40
  MAX_HOSTS    default 1000
  TIMEOUT      default 8  (seconds per request)
  DRY_RUN / PING
"""

import html
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

RECON_FILE = os.environ.get("RECON_FILE", "state/recon.json")
STATE_FILE = os.environ.get("STATE_FILE", "state/checks.json")
MAX_MSGS = int(os.environ.get("MAX_MSGS", "40"))
MAX_HOSTS = int(os.environ.get("MAX_HOSTS", "1000"))
TIMEOUT = int(os.environ.get("TIMEOUT", "8"))
DRY_RUN = os.environ.get("DRY_RUN", "") in ("1", "true", "yes")
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE   # probing error pages; don't fail on broken TLS

DEAD = {403, 404, 410, 503, None}


# ------------------------------------------------------------ takeover fingerprints
# Well-known, stable services. Not exhaustive — nuclei/dnsReaper cover the long tail.
FINGERPRINTS = [
    {"name": "AWS CloudFront", "cnames": [".cloudfront.net"],
     "sigs": ["ERROR: The request could not be satisfied"],
     "claim": ["CloudFront > Create distribution > any origin > Configure domains > add the hostname.",
               "No conflict there = name's free AWS-wide (uniqueness is global, not per-account).",
               "ACM TLS step needs DNS control you won't have for someone else's domain — that's",
               "expected, not a dead end. Report with this + the signature match; ask the program",
               "to finish verification on their side."]},
    {"name": "AWS S3", "cnames": ["s3.amazonaws", "s3-website", ".amazonaws.com"],
     "sigs": ["NoSuchBucket", "The specified bucket does not exist"],
     "claim": ["Bucket name is usually the CNAME target's first label, e.g. bucket.s3.amazonaws.com.",
               "aws s3 mb s3://<bucket-name>  — succeeds only if the name is truly free.",
               "Put a harmless index.html there as PoC, screenshot it loading on the real hostname."]},
    {"name": "GitHub Pages", "cnames": [".github.io"],
     "sigs": ["There isn't a GitHub Pages site here",
              "For root URLs (like http://example.com/) you must provide an index.html"],
     "claim": ["New public repo on your own account (any name) > add a file named CNAME containing",
               "the target hostname > Settings > Pages > enable, branch = main.",
               "Claiming is per-repo via that CNAME file, not a central namespace."]},
    {"name": "Heroku", "cnames": ["herokudns.com", "herokuapp.com", "herokussl"],
     "sigs": ["No such app", "no-such-app.html"],
     "claim": ["heroku create  (new app on your account)",
               "heroku domains:add <hostname> -a <your-app>",
               "Rejected = still claimed elsewhere; accepted = yours."]},
    {"name": "Shopify", "cnames": [".myshopify.com"],
     "sigs": ["Sorry, this shop is currently unavailable", "Only one step left"],
     "claim": ["Free Shopify dev store > Online Store > Domains > Connect existing domain >",
               "enter the target hostname."]},
    {"name": "Fastly", "cnames": [".fastly.net", "fastlylb"],
     "sigs": ["Fastly error: unknown domain",
              "Please check that this domain has been added to a service"],
     "claim": ["Fastly account > new Service > add the hostname as a Domain in that service's config."]},
    {"name": "Pantheon", "cnames": ["pantheonsite.io"],
     "sigs": ["The gods are wise", "404 error unknown site"],
     "claim": ["Free Pantheon account > new site > Domains > add the target hostname."]},
    {"name": "Tumblr", "cnames": ["domains.tumblr.com"],
     "sigs": ["Whatever you were looking for doesn't currently exist",
              "There's nothing here."],
     "claim": ["New Tumblr blog > Settings > use a custom domain > enter the target hostname."]},
    {"name": "WordPress", "cnames": [".wordpress.com"],
     "sigs": ["Do you want to register"],
     "claim": ["New WordPress.com site > domain mapping needs a paid plan upgrade — worth it only",
               "if payout looks likely to cover it."]},
    {"name": "Ghost", "cnames": [".ghost.io"],
     "sigs": ["The thing you were looking for is no longer here", "Domain error"],
     "claim": ["Ghost(Pro) site > custom domain under site settings (may need a paid plan)."]},
    {"name": "Surge.sh", "cnames": ["surge.sh"],
     "sigs": ["project not found"],
     "claim": ["npm i -g surge && surge  — when it asks for a domain, give the target hostname.",
               "Free, works immediately if the name's unclaimed."]},
    {"name": "Bitbucket", "cnames": ["bitbucket.io"],
     "sigs": ["Repository not found"],
     "claim": ["Same idea as GitHub Pages: new repo on your account, configure the custom domain",
               "in repo settings. Bitbucket's static-pages product has shifted over the years —",
               "double check it's still live before relying on this one."]},
    {"name": "Unbounce", "cnames": ["unbouncepages.com"],
     "sigs": ["The requested URL was not found on this server"],
     "claim": ["Unbounce account > page > custom domain setting > enter the target hostname."]},
    {"name": "Readme.io", "cnames": [".readme.io"],
     "sigs": ["Project doesnt exist... yet!"],
     "claim": ["Free ReadMe project > custom domain setting > enter the target hostname."]},
    {"name": "Azure", "cnames": [".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"],
     "sigs": ["404 Web Site not found"],
     "claim": ["Create a matching Azure resource (Web App / Cloud Service / Traffic Manager profile",
               "— match the CNAME type) > add the hostname as a custom domain binding."]},
    {"name": "Netlify", "cnames": [".netlify.app", ".netlify.com"],
     "sigs": ["Not Found - Request ID"],
     "claim": ["New Netlify site (drag-and-drop a folder is enough) > Domain management >",
               "Add custom domain > enter the target hostname."]},
]


# --------------------------------------------------------------- leak validators
def _git_head(b):
    return bool(re.match(r"^(ref:\s+refs/|[0-9a-f]{40}\b)", b.strip()))


def _git_config(b):
    return "[core]" in b and "repositoryformatversion" in b


def _env(b):
    if "<html" in b.lower() or "<!doctype" in b.lower():
        return False
    return len(re.findall(r"(?m)^[A-Z][A-Z0-9_]{1,}=", b)) >= 2


def _aws(b):
    return "aws_access_key_id" in b.lower()


LEAK_PATHS = [
    ("/.git/HEAD", _git_head, "exposed .git"),
    ("/.git/config", _git_config, "exposed .git/config"),
    ("/.env", _env, "exposed .env"),
    ("/.env.local", _env, "exposed .env.local"),
    ("/.aws/credentials", _aws, "exposed AWS credentials"),
]


# ----------------------------------------------------------------------- http
def fetch(url):
    """Return (status:int|None, body:str, final_url:str) — final_url is where we
    landed after redirects, which is how a GitHub private-Pages auth gate gets
    noticed. Never raises."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "recon-checks/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_SSL) as r:
            return r.status, r.read(16384).decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(16384).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, getattr(e, "url", url)
    except Exception:
        return None, "", url


def base_url(host, info):
    u = info.get("url")
    if u:
        return u.rstrip("/")
    return "https://" + host


# ---------------------------------------------------------------------- checks
def check_takeover(host, info):
    cnames = info.get("cname") or []
    if not cnames:
        return None
    joined = " ".join(cnames).lower()
    fp = next((f for f in FINGERPRINTS
               if any(c in joined for c in f["cnames"])), None)
    if not fp:
        return None
    st, body, final_url = fetch(base_url(host, info) + "/")
    # GitHub redirects a CLAIMED-but-private Pages site through its own auth gate —
    # that's proof the site exists and is owned, not a dangling-CNAME candidate.
    if "github.com/pages/auth" in final_url or \
       "which does not have access to this Page" in body:
        return None
    if any(sig in body for sig in fp["sigs"]):
        return {"kind": "takeover", "host": host, "service": fp["name"],
                "cname": cnames, "status": st, "confirmed": True,
                "claim": fp.get("claim")}
    if st in DEAD:
        return {"kind": "takeover?", "host": host, "service": fp["name"],
                "cname": cnames, "status": st, "confirmed": False}
    return None


def check_leaks(host, info):
    base = base_url(host, info)
    # soft-404 baseline: a random path that should not exist
    _, baseline, _ = fetch(base + "/zz-%s-nope" % int(time.time()))
    out = []
    for path, valid, label in LEAK_PATHS:
        st, body, _ = fetch(base + path)
        if st == 200 and body and body != baseline and valid(body):
            snippet = body.strip().splitlines()[0][:80] if body.strip() else ""
            out.append({"kind": "leak", "host": host, "path": path,
                        "label": label, "snippet": snippet})
    return out


# ---------------------------------------------------------------------- format
def esc(s):
    return html.escape(str(s), quote=False)


def key_of(f):
    if f["kind"] == "leak":
        return f"leak:{f['host']}:{f['path']}"
    return f"{f['kind']}:{f['host']}"


def rank(f):
    # confirmed takeover & .git/.env first; possible takeover last
    order = {"takeover": 0, "leak": 1, "takeover?": 2}
    return (order.get(f["kind"], 3), f["host"])


def group_shared_takeovers(items):
    """Confirmed takeovers that share the exact same CNAME target are very likely ONE
    underlying resource (one distribution/bucket/app with many alternate hostnames
    attached), not N independent findings — claiming/verifying one tells you the
    status of all of them. Groups those together; everything else passes through
    unchanged."""
    buckets = {}
    rest = []
    for f in items:
        if f["kind"] == "takeover" and f.get("confirmed"):
            key = (f["service"], tuple(sorted(f["cname"])))
            buckets.setdefault(key, []).append(f)
        else:
            rest.append(f)
    grouped, rest2 = [], rest
    for (service, cname), group in buckets.items():
        if len(group) > 1:
            grouped.append({"group": True, "service": service, "cname": list(cname),
                            "hosts": sorted(f["host"] for f in group),
                            "claim": group[0].get("claim")})
        else:
            rest2.append(group[0])
    return grouped + rest2


def format_finding(f):
    if f.get("group"):
        lines = [f"<b>\U0001F534 TAKEOVER (likely) \u00b7 {esc(f['service'])}</b>",
                 f"<b>{len(f['hosts'])} hostnames share this CNAME \u2014 verify ONCE, "
                 f"applies to all:</b>"]
        for h in f["hosts"]:
            lines.append(f"<code>{esc(h)}</code>")
        lines.append("CNAME: " + esc(", ".join(f["cname"][:2])))
        lines.append("\u21B3 matched signature on every one of them")
        if f.get("claim"):
            lines.append("")
            lines.append("<b>To claim (once \u2014 not per hostname):</b>")
            for step in f["claim"]:
                lines.append(esc(step))
        return "\n".join(lines)

    if f["kind"] == "leak":
        lines = [f"<b>\U0001F534 LEAK · {esc(f['label'])}</b>",
                 f"<code>{esc(f['host'] + f['path'])}</code>"]
        if f["snippet"]:
            lines.append("\u21B3 <code>" + esc(f["snippet"]) + "</code>")
        lines.append(f"\U0001F517 https://{esc(f['host'])}{esc(f['path'])}")
        return "\n".join(lines)

    confirmed = f["confirmed"]
    head = ("\U0001F534 TAKEOVER (likely)" if confirmed
            else "\U0001F7E1 POSSIBLE TAKEOVER")
    lines = [f"<b>{head} · {esc(f['service'])}</b>",
             f"<code>{esc(f['host'])}</code>",
             "CNAME: " + esc(", ".join(f["cname"][:3]))]
    tail = f"HTTP {f['status']}"
    tail += ' · matched signature' if confirmed else ' · no signature — verify manually'
    lines.append("\u21B3 " + tail)
    lines.append(f"\U0001F517 https://{esc(f['host'])}")

    if confirmed and f.get("claim"):
        lines.append("")
        lines.append("<b>To claim it yourself:</b>")
        for step in f["claim"]:
            lines.append(esc(step))

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
        return set(json.load(open(STATE_FILE)).get("findings", []))
    except Exception:
        return set()


def save_state(keys):
    os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
    json.dump({"findings": sorted(keys),
               "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
              open(STATE_FILE, "w"), indent=0)


# ------------------------------------------------------------------------ main
def main():
    if not TOKEN or not CHAT:
        sys.exit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")

    if os.environ.get("PING", "") in ("1", "true", "yes"):
        tg_send("\u2705 checks-monitor connected.")
        print("ping sent")
        return

    hosts = load_recon()
    if not hosts:
        print(f"[recon] no inventory in {RECON_FILE} yet — run recon first. Nothing to do.")
        return

    # only hosts that are reachable web (recon recorded a status)
    web = {h: i for h, i in hosts.items() if i.get("status") is not None}
    print(f"[checks] {len(web)} web host(s) from {len(hosts)} tracked")

    seen = load_state()
    findings = []
    for n, (host, info) in enumerate(sorted(web.items())):
        if n >= MAX_HOSTS:
            print(f"[checks] host cap {MAX_HOSTS} reached"); break
        t = check_takeover(host, info)
        if t:
            findings.append(t)
        findings.extend(check_leaks(host, info))
        time.sleep(0.2)

    findings.sort(key=rank)
    new = [f for f in findings if key_of(f) not in seen]
    print(f"[checks] {len(findings)} finding(s), {len(new)} new")

    to_send = group_shared_takeovers(new)
    sent = 0
    for f in to_send:
        if sent >= MAX_MSGS:
            tg_send(f"\u2795 +{len(to_send) - sent} more new findings this run "
                    f"(raise MAX_MSGS).")
            break
        tg_send(format_finding(f))
        sent += 1
        time.sleep(1)

    if new:
        save_state(seen | {key_of(f) for f in new})
        print(f"[state] +{len(new)} findings recorded")


if __name__ == "__main__":
    main()
