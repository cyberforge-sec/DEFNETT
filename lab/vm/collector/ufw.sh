#!/bin/bash
# DEFNETT lab - firewall VM collector (192.168.56.20). Jalankan sebagai root.
set -euo pipefail
ufw default deny incoming
ufw default allow outgoing
ufw allow from 192.168.56.1  to any port 22   proto tcp comment "SSH admin host"
ufw allow from 192.168.56.1  to any port 8090 proto tcp comment "dashboard/API admin"
ufw allow from 192.168.56.11 to any port 8090 proto tcp comment "telemetry server-a"
ufw allow from 192.168.56.12 to any port 8090 proto tcp comment "telemetry server-b"
printf "y\n" | ufw enable
ufw status numbered
