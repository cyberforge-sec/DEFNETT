#!/bin/sh
# build.sh — bangun lab DEFNETT dan siapkan demo dengan satu perintah.
#
# Alasan file ini ada: macOS di volume eksternal (=BLUE) kadang menyisipkan
# berkas AppleDouble (._*.yaml dan teman-temannya) sebelah file asli. Build
# Docker akan gagal dengan "failed to xattr ... operation not permitted"
# hanya karena Berkas tak terlihat itu. Jadi dibersihkan dulu tiap kali.
#
# Pemakaian (dari root repo):  sh lab/build.sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose() { docker compose -f lab/compose.yaml -f lab/compose.canary.yaml "$@"; }

printf '%s\n' '[1/4] Bersihkan berkas AppleDouble macOS (._*)...'
find "$root_dir/lab" -name '._*' -type f -delete
printf '   sisa ._* : %s\n' "$(find "$root_dir/lab" -name '._*' | wc -l | tr -d ' ')"

printf '%s\n' '[2/4] Membangun dan menghidupkan lab (compose build)...'
cd "$root_dir"
compose up -d --build --wait

printf '%s\n' '[3/4] Mengisi data demo dan menyimpan salinan master kunci...'
for host in server-a server-b; do
    if ! compose exec -T "$host" test -f /data/etc/kunci1.dat; then
        compose exec -T "$host" sh -s "$host" < lab/seed-fs.sh
    fi
done
compose restart remediator-a remediator-b agent-a agent-b

printf '%s\n' '[4/4] Status kontainer:'
sleep 5
compose ps --format 'table {{.Name}}\t{{.Status}}'

printf '\n%s\n' 'Siap. Dashboard: http://127.0.0.1:8090/  -  App lewat HAProxy: http://127.0.0.1:8080/'
printf '%s\n' 'Buka tab Patrol, pilih server, lalu tekan SERANG!.'
