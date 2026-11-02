#!/bin/sh
# DEFNETT lab - pasang serangan demo yang terhubung ke HAProxy asli. Jalankan sebagai root di tiap VM.
# Urutan: server-a, server-b dulu (worker), collector terakhir.
# Pemakaian: sh deploy-real-attack.sh server-a|server-b|collector [folder-sumber]
# File lama disalin dulu ke <nama>.bak-<waktu>. Collector berpindah dari DRY_RUN ke ACTIVE_LAB.
set -eu

ROLE="${1:-}"
SOURCE="${2:-/tmp/defnett-deploy}"
STAMP="$(date +%Y%m%d%H%M%S)"

put() {
  [ ! -e "$2" ] || cp -p "$2" "$2.bak-$STAMP"
  install -m "$3" -o root -g "$4" "$1" "$2"
}

setenv() {
  if grep -q "^$2=" "$1"; then
    sed -i "s|^$2=.*|$2=$3|" "$1"
  else
    printf '%s=%s\n' "$2" "$3" >> "$1"
  fi
}

case "$ROLE" in
  server-a|server-b)
    cp -p "/etc/defnett/$ROLE.env" "/etc/defnett/$ROLE.env.bak-$STAMP"
    put "$SOURCE/remediator.py" /opt/defnett/remediator.py 644 root
    setenv "/etc/defnett/$ROLE.env" LAB_ATTACK_SIMULATION true
    systemctl restart defnett-remediator
    systemctl is-active defnett-remediator
    ;;
  collector)
    cp -p /etc/defnett/collector.env "/etc/defnett/collector.env.bak-$STAMP"
    put "$SOURCE/collector.py" /opt/defnett/collector.py 644 root
    for name in index.html dashboard.css dashboard.js patrol.css patrol.js; do
      put "$SOURCE/dashboard/$name" "/opt/defnett/dashboard/$name" 644 root
    done
    setenv /etc/defnett/collector.env ENABLE_LAB_AUTOREPAIR true
    setenv /etc/defnett/collector.env DEMO_REPAIR_HOST all
    setenv /etc/defnett/collector.env DEMO_REPAIR_DELAY_SECONDS 15
    systemctl restart defnett-collector
    systemctl is-active defnett-collector
    ;;
  *)
    echo "pemakaian: sh deploy-real-attack.sh server-a|server-b|collector [folder-sumber]" >&2
    exit 2
    ;;
esac
