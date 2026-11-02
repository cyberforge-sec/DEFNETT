#!/bin/sh
# attack.sh — memerankan pencuri dari luar lewat HAProxy, seperti di animasi patrol:
#   1) mengintip file yang memang publik (dibolehkan, lalu tertarik),
#   2) menebak-nebak nama file sensitif (ditolak 403),
#   3) membidik kunci rahasia etc/kunci1.dat dan etc/kunci2.dat (ditolak 403),
#   4) mencoba membawa pulang kunci dengan ?download=1 (ditolak lagi).
# Setiap penolakan dicatat collector sebagai event denied -> animasi pencuri
# di dashboard Patrol bereaksi proactively.
#
# Pemakaian (dari root repo):  sh lab/attack.sh [base_haproxy] [collector]
# Default: http://127.0.0.1:8080 dan http://127.0.0.1:8090
set -eu

base_url=${1:-http://127.0.0.1:8080}
collector_url=${2:-http://127.0.0.1:8090}

say() { printf '\n%s\n' "$1"; }

# Request yang diharapkan SUKSES; skrip berhenti kalau ternyata gagal.
baca() {
    path=$1
    curl --fail --silent --show-error "$base_url/files/$path"
}

# Request yang diharapkan DITOLAK; status dilaporkan, bukan menghentikan skrip.
serang() {
    path=$1
    extra=${2:-}
    code=$(curl --silent --show-error --output /dev/null \
        --write-out '%{http_code}' "$base_url/files/$path$extra")
    case "$code" in
        403) printf '  DITOLAK   HTTP 403  %s%s\n' "$path" " ${extra:-}" ;;
        200) printf '  BOCOR!    HTTP 200  %s%s\n' "$path" " ${extra:-}" ;;
        *)   printf '  ???       HTTP %s  %s%s\n' "$code" "$path" " ${extra:-}" ;;
    esac
}

say '[1] Pencuri masuk: mengintip halaman depan dan info sistem'
curl --fail --silent "$base_url/" | head -n 1 | sed 's/^/  \/                -> /'
curl --fail --silent "$base_url/files/etc/os-release" | head -n 2 | sed 's/^/  os-release:    /'
curl --fail --silent --output /dev/null --write-out '  etc/hostname    HTTP %{http_code}\n' "$base_url/files/etc/hostname" || true
sleep 1

say '[2] Mengintip catatan publik yang tidak terkunci'
for i in 03 11 22; do
    isi=$(curl --fail --silent "$base_url/files/home/kartika/notes/note-$i.txt")
    printf '  note-%s.txt -> %s\n' "$i" "$isi"
done
curl --fail --silent --output /dev/null --write-out '  audit-01.txt    HTTP %{http_code}\n' "$base_url/files/home/kartika/reports/audit-01.txt" || true
sleep 1

say '[3] Mulai mencari-cari: tebak nama file sensitif (semua diharapkan ditolak)'
serang etc/kunci.dat
serang etc/secret.dat
serang etc/password
serang var/log/syslog
serang opt/defnett/deploy.txt
serang root/README.txt
sleep 1

say '[4] Mengunci target: kunci rahasia di etc/'
serang etc/kunci1.dat
serang etc/kunci2.dat
sleep 1

say '[5] Mencoba membawa pulang kunci (?download=1)'
serang etc/kunci1.dat '?download=1'
serang etc/kunci2.dat '?download=1'

say '[6] Jejaknya di collector (event denied teritori patrol)'
python3 - "$collector_url" <<'PY'
import json, sys, urllib.request

with urllib.request.urlopen(sys.argv[1] + "/api/patrol/state", timeout=5) as response:
    data = json.load(response)
events = data.get("events") or []
recent = [e for e in events if e.get("status") == "blocked" or "kunci" in str(e.get("path", ""))][-10:]
print(f"  total event patrol tersimpan: {len(events)} | denied/kunci terakhir: {len(recent)}")
for e in recent:
    print(f"  {str(e.get('ts',''))[:19]} {str(e.get('host_id','')):<9} "
          f"{str(e.get('action','')):<9} {str(e.get('status','')):<8} {e.get('path','')}")
PY

printf '\n%s\n' 'Selesai: kunci tidak pernah keluar dari server; setiap percobaan tercatat.'
