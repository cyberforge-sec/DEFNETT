#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$root_dir/lab/compose.yaml"

printf '%s\n' '1. Permintaan melalui HAProxy:'
curl --fail --silent http://127.0.0.1:8080/

printf '\n%s\n' '2. Buat perubahan file pada Server A (etc/new-config.txt):'
docker compose -f "$compose_file" exec -T server-a python -c "from pathlib import Path; Path('/data/etc/new-config.txt').write_text('demo change\n', encoding='utf-8')"
sleep 5

printf '\n%s\n' '3. Event, keputusan, dan hash chain yang diterima collector:'
curl --fail --silent http://127.0.0.1:8090/v1/events
printf '\n'

printf '\n%s\n' '4. Permintaan berikutnya tetap dilayani oleh backend yang sehat:'
curl --fail --silent http://127.0.0.1:8080/
