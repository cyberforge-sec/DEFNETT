#!/bin/sh
# DEFNETT lab - pasang pintu per port di Patrol. Jalankan sebagai root di tiap VM.
# Urutan: collector dulu, lalu server-a dan server-b.
# Pemakaian: sh deploy-port-doors.sh server-a|server-b|collector [folder-sumber]
# File lama disalin dulu ke <nama>.bak-<waktu>.
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
    put "$SOURCE/agent.py" /opt/defnett/agent.py 640 defnett
    setenv "/etc/defnett/$ROLE.env" AUTH_LOG /var/log/auth.log
    setenv "/etc/defnett/$ROLE.env" WEB_LOG /var/log/apache2/access.log
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
    echo "pemakaian: sh deploy-port-doors.sh server-a|server-b|collector [folder-sumber]" >&2
    exit 2
    ;;
esac
