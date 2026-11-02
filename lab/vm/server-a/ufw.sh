#!/bin/bash
# DEFNETT lab - firewall VM server-a (192.168.56.11). Jalankan sebagai root.
set -euo pipefail
ufw default deny incoming
ufw default allow outgoing
ufw allow from 192.168.56.1  to any port 22   proto tcp comment "SSH admin host"
ufw allow from 192.168.56.1  to any port 8080 proto tcp comment "app admin"
ufw allow from 192.168.56.1  to any port 8091 proto tcp comment "remediator admin"
ufw allow from 192.168.56.10 to any port 8080 proto tcp comment "healthcheck haproxy"
ufw allow from 192.168.56.20 to any port 8080 proto tcp comment "probe trafik collector"
ufw allow from 192.168.56.20 to any port 8091 proto tcp comment "repair collector"
printf "y\n" | ufw enable
ufw status numbered
