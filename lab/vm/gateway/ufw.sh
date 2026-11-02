#!/bin/bash
# DEFNETT lab - gateway firewall. Jalankan sebagai root di VM gateway.
# Urutan aman: aturan SSH dulu, enable terakhir, agar admin tidak terkunci.
set -euo pipefail
ufw default deny incoming
ufw default allow outgoing
ufw allow from 192.168.56.1  to any port 22   proto tcp comment "SSH admin host"
ufw allow from 192.168.56.1  to any port 8080 proto tcp comment "app host"
ufw allow from 192.168.56.20 to any port 8080 proto tcp comment "probe collector"
ufw allow from 192.168.56.20 to any port 9999 proto tcp comment "API runtime collector"
printf "y\n" | ufw enable
ufw status numbered
