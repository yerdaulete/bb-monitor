#!/usr/bin/env bash
# vps-setup.sh — one-time bootstrap for the endpoints (#4) and cve (#6) modules.
# Run ONCE on a fresh Ubuntu VPS, as root (or a sudo user), via SSH:
#
#   git clone https://github.com/<you>/bb-monitor.git && cd bb-monitor && bash vps-setup.sh
#
# Safe to re-run: it skips what's already done and never overwrites an existing .env.
set -e

step() { echo; echo "=== $1 ==="; }

step "1/7 System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git python3 golang-go ca-certificates curl >/dev/null
timedatectl set-timezone UTC 2>/dev/null || true
echo "done."

step "2/7 Install katana, nuclei, jsluice (Go tools)"
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"
echo "  -> katana (crawler)"
go install github.com/projectdiscovery/katana/cmd/katana@latest || echo "  !! katana install failed, continuing" >&2
echo "  -> nuclei (CVE/vuln templates)"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "  !! nuclei install failed, continuing" >&2
echo "  -> jsluice (JS endpoint/secret extraction)"
go install github.com/BishopFox/jsluice/cmd/jsluice@latest || echo "  !! jsluice install failed, continuing" >&2
for bin in katana nuclei jsluice; do
  if [ -f "$GOPATH/bin/$bin" ]; then
    ln -sf "$GOPATH/bin/$bin" "/usr/local/bin/$bin"
    echo "  $bin -> /usr/local/bin/$bin  ($($bin -version 2>&1 | head -1 || echo installed))"
  else
    echo "  !! $bin did NOT install — go module path may have changed." >&2
    echo "     Paste this error back and we'll fix the exact install command:" >&2
    echo "     go install github.com/projectdiscovery/$bin/cmd/$bin@latest" >&2
  fi
done

step "3/7 Repo location"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -d "$REPO_DIR/.git" ]; then
  echo "This doesn't look like a git clone of bb-monitor (no .git here)." >&2
  echo "Run: git clone https://github.com/<you>/bb-monitor.git && cd bb-monitor && bash vps-setup.sh" >&2
  exit 1
fi
cd "$REPO_DIR"
echo "using $REPO_DIR"

step "4/7 Telegram credentials (.env)"
if [ -f .env ]; then
  echo ".env already exists — leaving it as is."
else
  read -rp "Telegram bot token: " TG_TOKEN
  read -rp "Telegram chat id: " TG_CHAT
  cat > .env <<EOF
TELEGRAM_BOT_TOKEN=$TG_TOKEN
TELEGRAM_CHAT_ID=$TG_CHAT
EOF
  chmod 600 .env
  echo "wrote .env (chmod 600, never committed — it's gitignored)"
fi

step "5/7 run.sh wrapper"
cat > run.sh <<'EOF'
#!/usr/bin/env bash
# Called by cron: refreshes scope.txt/recon.json from the repo, loads secrets, runs
# one script, logs output. State files these scripts write (state/endpoints.json,
# state/cve.json) are LOCAL ONLY — never committed or pushed.
cd "$(dirname "${BASH_SOURCE[0]}")"
git pull --quiet origin main 2>>logs/git.log || echo "$(date -u) git pull failed, using existing local copy" >> logs/git.log
set -a
source .env
set +a
mkdir -p logs
python3 "$1" >> "logs/$(basename "$1" .py).log" 2>&1
EOF
chmod +x run.sh
mkdir -p logs
echo "done."

step "6/7 Cron schedule (UTC)"
SELF_LINE_EP="0 1,7,13,19 * * * $REPO_DIR/run.sh endpoints.py"
SELF_LINE_CVE="0 2,8,14,20 * * * $REPO_DIR/run.sh cve.py"
( crontab -l 2>/dev/null | grep -v "run.sh endpoints.py" | grep -v "run.sh cve.py" ; \
  echo "$SELF_LINE_EP" ; echo "$SELF_LINE_CVE" ) | crontab -
echo "installed:"
echo "  $SELF_LINE_EP"
echo "  $SELF_LINE_CVE"
echo "(1h and 2h after recon's :00/:30 slots, so recon.json is fresh when these run)"

step "7/7 Connectivity test"
echo "Sending a Telegram ping for each module..."
( set -a; source .env; set +a; PING=1 python3 endpoints.py ) || true
( set -a; source .env; set +a; PING=1 python3 cve.py ) || true

echo
echo "============================================================"
echo " Setup complete. Check Telegram for two '✅ ... connected' pings."
echo
echo " Next: make sure scope.txt has your targets and recon has run"
echo " at least once (state/recon.json must exist) — these two"
echo " modules crawl/scan whatever recon already found."
echo
echo " Logs:    $REPO_DIR/logs/"
echo " Run now: ./run.sh endpoints.py   or   ./run.sh cve.py"
echo "============================================================"
