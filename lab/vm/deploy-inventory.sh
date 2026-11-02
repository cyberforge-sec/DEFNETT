#!/bin/sh
# DEFNETT lab - pasang inventaris file system. Jalankan sebagai root di tiap VM.
# Pemakaian: sh deploy-inventory.sh server-a|server-b|collector [folder-sumber]
# File lama disalin dulu ke <nama>.bak-<waktu> agar bisa dikembalikan.
set -eu

ROLE="${1:-}"
SOURCE="${2:-/tmp/defnett-deploy}"
STAMP="$(date +%Y%m%d%H%M%S)"

put() {
  [ ! -e "$2" ] || cp -p "$2" "$2.bak-$STAMP"
  install -m "$3" -o root -g "$4" "$1" "$2"
}

case "$ROLE" in
  server-a|server-b)
    ENV_FILE="/etc/defnett/$ROLE.env"
    put "$SOURCE/agent.py" /opt/defnett/agent.py 640 defnett
    grep -q '^INVENTORY_ROOT=' "$ENV_FILE" || printf 'INVENTORY_ROOT=/\nINVENTORY_SECONDS=300\n' >> "$ENV_FILE"
    systemctl restart defnett-agent
    systemctl is-active defnett-agent
    ;;
  collector)
    put "$SOURCE/collector.py" /opt/defnett/collector.py 644 root
    for name in index.html dashboard.css dashboard.js patrol.css patrol.js; do
      put "$SOURCE/dashboard/$name" "/opt/defnett/dashboard/$name" 644 root
    done
    systemctl restart defnett-collector
    systemctl is-active defnett-collector
    ;;
  *)
    echo "pemakaian: sh deploy-inventory.sh server-a|server-b|collector [folder-sumber]" >&2
    exit 2
    ;;
esac
