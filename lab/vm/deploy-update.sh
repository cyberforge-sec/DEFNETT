#!/bin/sh
# DEFNETT lab - pasang pembaruan di satu VM. Jalankan sebagai root; peran dibaca dari hostname.
# Urutan: server-a, server-b, lalu collector, agar token aktif setelah pengirimnya siap.
# File lama disalin ke <nama>.bak-<waktu>. Folder sumber dihapus setelah berhasil karena memuat token.
set -eu

ROLE="$(hostname)"
SOURCE="${1:-/tmp/defnett-deploy}"
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

[ -d "$SOURCE" ] || { echo "paket tidak ditemukan di $SOURCE, tidak ada yang diubah" >&2; exit 1; }
TOKEN=""
[ ! -s "$SOURCE/token" ] || TOKEN="$(cat "$SOURCE/token")"

case "$ROLE" in
  server-a|server-b)
    ENV_FILE="/etc/defnett/$ROLE.env"
    cp -p "$ENV_FILE" "$ENV_FILE.bak-$STAMP"
    put "$SOURCE/agent.py" /opt/defnett/agent.py 640 defnett
    put "$SOURCE/app.py" /opt/defnett/app.py 644 root
    put "$SOURCE/remediator.py" /opt/defnett/remediator.py 644 root
    [ -z "$TOKEN" ] || setenv "$ENV_FILE" LAB_API_TOKEN "$TOKEN"
    systemctl restart defnett-remediator defnett-agent defnett-app
    systemctl is-active defnett-remediator defnett-agent defnett-app
    ;;
  collector)
    ENV_FILE=/etc/defnett/collector.env
    cp -p "$ENV_FILE" "$ENV_FILE.bak-$STAMP"
    put "$SOURCE/collector.py" /opt/defnett/collector.py 644 root
    for name in index.html dashboard.css dashboard.js patrol.css patrol.js; do
      put "$SOURCE/dashboard/$name" "/opt/defnett/dashboard/$name" 644 root
    done
    [ -z "$TOKEN" ] || setenv "$ENV_FILE" LAB_API_TOKEN "$TOKEN"
    systemctl restart defnett-collector
    systemctl is-active defnett-collector
    ;;
  *)
    echo "hostname tidak dikenal: $ROLE" >&2
    exit 2
    ;;
esac

rm -rf "$SOURCE"
echo "selesai: $ROLE"
