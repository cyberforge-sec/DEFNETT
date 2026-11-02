#!/bin/sh
# DEFNETT lab - perbaiki beranda WordPress 5.0 yang selalu "Page not found" di PHP 8.
# Penyebab: di PHP 8, "" < 0 bernilai true, jadi semua halaman daftar (beranda, kategori, feed)
# ditandai 404. Perbaikan: bandingkan sebagai integer, sama seperti perbaikan resmi WordPress.
# Jalankan sebagai root di Server A dan Server B. Aman dijalankan ulang; file asli disimpan sebagai .bak-<waktu>.
set -eu

FILE=/var/www/html/wp-includes/class-wp-query.php
OLD="|| \$qv['p'] < 0 ) {"
NEW="|| (int) \$qv['p'] < 0 ) {"
STAMP="$(date +%Y%m%d%H%M%S)"

[ -f "$FILE" ] || { echo "tidak ditemukan: $FILE" >&2; exit 1; }
if grep -qF "(int) \$qv['p'] < 0" "$FILE"; then
  echo "sudah diperbaiki, tidak ada yang diubah"
  exit 0
fi
[ "$(grep -cF "$OLD" "$FILE")" = 1 ] || { echo "baris target tidak ditemukan tepat satu kali, dibatalkan" >&2; exit 1; }

cp -p "$FILE" "$FILE.bak-$STAMP"
sed -i "s/|| \\\$qv\['p'\] < 0 ) {/|| (int) \$qv['p'] < 0 ) {/" "$FILE"

if ! grep -qF "$NEW" "$FILE" || ! php -l "$FILE" >/dev/null; then
  cp -p "$FILE.bak-$STAMP" "$FILE"
  echo "perubahan gagal diverifikasi, file dikembalikan" >&2
  exit 1
fi
chown --reference="$FILE.bak-$STAMP" "$FILE"
systemctl reload apache2
echo "selesai: $(grep -nF "$NEW" "$FILE" | cut -d: -f1) | backup $FILE.bak-$STAMP"
