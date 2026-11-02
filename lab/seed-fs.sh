#!/bin/sh
# seed-fs.sh — susun isi /data menjadi pohon direktori ala Linux di dalam container server DEFNETT.
# Pemakaian (dari root repo):
#   docker exec -i lab-server-a-1 sh -s server-a < lab/seed-fs.sh
#   docker exec -i lab-server-b-1 sh -s server-b < lab/seed-fs.sh
HOST_ID="${1:-server}"
DATA="/data"

[ -d "$DATA" ] || { echo "folder $DATA tidak ditemukan; jalankan di dalam container server"; exit 1; }

mkdir -p "$DATA/bin" "$DATA/boot/grub" "$DATA/etc" \
  "$DATA/home/kartika/notes" "$DATA/home/kartika/reports" "$DATA/home/dima" \
  "$DATA/opt/defnett" "$DATA/root" "$DATA/usr/bin" "$DATA/usr/share/defnett" \
  "$DATA/srv" "$DATA/var/log" "$DATA/var/lib/defnett"

# Tata letak flat dulu dibersihkan; index.txt tetap di akar (app menyajikan / ke sini).
rm -f "$DATA/index.txt" "$DATA"/note-*.txt "$DATA/kunci1.dat" "$DATA/kunci2.dat" "$DATA/new-config.txt"
printf "Sample content on %s\n" "$HOST_ID" > "$DATA/index.txt"

# bin
printf "placeholder bin sh di %s\n" "$HOST_ID" > "$DATA/bin/sh"
printf "placeholder bin ls di %s\n" "$HOST_ID" > "$DATA/bin/ls"
printf "placeholder bin cat di %s\n" "$HOST_ID" > "$DATA/bin/cat"

# boot
cat > "$DATA/boot/grub/grub.cfg" <<EOF
set default=0
menuentry "DEFNETT lab kernel" {
  linux /boot/vmlinuz-lab quiet
}
EOF

# etc
printf "%s\n" "$HOST_ID" > "$DATA/etc/hostname"
cat > "$DATA/etc/hosts" <<EOF
127.0.0.1 localhost
10.20.0.10 server-a
10.20.0.11 server-b
EOF
cat > "$DATA/etc/os-release" <<EOF
ID=defnett
NAME="DEFNETT Lab OS"
VERSION="1 (lab)"
PRETTY_NAME="DEFNETT Lab OS 1"
EOF
cat > "$DATA/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
defnett:x:10001:10001:lab service account:/home/kartika:/bin/sh
EOF
printf "Selamat datang di node %s.\n" "$HOST_ID" > "$DATA/etc/motd"

# kunci rahasia — TIDAK terdaftar di PATROL_PUBLIC_FILES, request app langsung 403 denied
cat > "$DATA/etc/kunci1.dat" <<EOF
SECRET kunci1 — jangan dibagikan ($HOST_ID)
Label: DEFNETT-LAB-KEY-1
EOF
cat > "$DATA/etc/kunci2.dat" <<EOF
SECRET kunci2 — jangan dibagikan ($HOST_ID)
Label: DEFNETT-LAB-KEY-2
EOF

# catatan konfigurasi (bekas file demo flat dipindah ke tempatnya)
printf "Konfigurasi demo node %s; dari seed-fs.sh.\n" "$HOST_ID" > "$DATA/etc/new-config.txt"

# home
printf "# bashrc kartika di %s\nalias ll='ls -l'\n" "$HOST_ID" > "$DATA/home/kartika/.bashrc"
printf "# bashrc dima di %s\nPS1='dima@defnett:\\w\\$ '\n" "$HOST_ID" > "$DATA/home/dima/.bashrc"

i=1
while [ "$i" -le 30 ]; do
  n=$(printf "%02d" "$i")
  printf "Note %s di %s — contoh isi arsip DEFNETT.\n" "$n" "$HOST_ID" > "$DATA/home/kartika/notes/note-$n.txt"
  i=$((i + 1))
done
printf "Audit pertama node %s: seluruh service healthy.\n" "$HOST_ID" > "$DATA/home/kartika/reports/audit-01.txt"
printf "Audit kedua node %s: trafik lewat HAProxy stabil.\n" "$HOST_ID" > "$DATA/home/kartika/reports/audit-02.txt"

# root
printf "Beranda operator root (node %s). Tidak ada berkas sensitif di sini.\n" "$HOST_ID" > "$DATA/root/README.txt"

# opt, usr, srv, var
printf "defnett-lab 1.0-patched\n" > "$DATA/opt/defnett/VERSION"
printf "Playbook canary aktif; probe trafik 1 detik.\n" > "$DATA/opt/defnett/deploy.txt"
printf "placeholder python3 di %s\n" "$HOST_ID" > "$DATA/usr/bin/python3"
cat > "$DATA/usr/share/defnett/policy.txt" <<EOF
playbook: isolasi -> karantina -> verifikasi -> rejoin
worker hanya menulis volume host pasangannya
EOF
printf "Mount point lab.\n" > "$DATA/srv/README.txt"
j=1
while [ "$j" -le 20 ]; do
  m=$((j % 10))
  printf "Sep 25 09:%02d:00 node %s service ok; pesan log #%s\n" "$((10 + m))" "$HOST_ID" "$j" >> "$DATA/var/log/syslog"
  j=$((j + 1))
done
printf "Sep 25 09:15:01 node %s auth: heartbeat agent sukses\n" "$HOST_ID" > "$DATA/var/log/auth.log"
cat > "$DATA/var/lib/defnett/state.json" <<EOF
{"host": "$HOST_ID", "mode": "ACTIVE_LAB", "baseline": "hash-chain"}
EOF

printf "seed %s selesai: %s file, %s direktori\n" \
  "$HOST_ID" "$(find "$DATA" -type f | wc -l)" "$(find "$DATA" -type d | wc -l)"
