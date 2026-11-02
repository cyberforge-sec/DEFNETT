#!/bin/sh
# build.sh — bangun dan jalankan ulang seluruh lab DEFNETT dengan satu perintah.
#
# Alasan file ini ada: macOS di volume eksternal (=BLUE) kadang menyisipkan
# berkas AppleDouble (._*.yaml dan teman-temannya) sebelah file asli. Build
# Docker akan gagal dengan "failed to xattr ... operation not permitted"
# hanya karena Berkas tak terlihat itu. Jadi dibersihkan dulu tiap kali.
#
# Pemakaian (dari root repo):  sh lab/build.sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

printf '%s\n' '[1/3] Bersihkan berkas AppleDouble macOS (._*)...'
find "$root_dir/lab" -name '._*' -type f -delete
printf '   sisa ._* : %s\n' "$(find "$root_dir/lab" -name '._*' | wc -l | tr -d ' ')"

printf '%s\n' '[2/3] Membangun dan menghidupkan lab (compose build)...'
cd "$root_dir"
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml up -d --build

printf '%s\n' '[3/3] Status kontainer:'
sleep 5
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml ps --format 'table {{.Name}}\t{{.Status}}'

printf '\n%s\n' 'Siap. Dashboard: http://127.0.0.1:8090/  -  App lewat HAProxy: http://127.0.0.1:8080/'
