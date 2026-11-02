#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose_file="$root_dir/lab/compose.yaml"
canary_file="$root_dir/lab/compose.canary.yaml"
target_host=${1:-server-a}
mode=${2:-canary}
case "$target_host" in
    server-a) survivor_host=server-b ;;
    server-b) survivor_host=server-a ;;
    *) printf '%s\n' 'Target harus server-a atau server-b.' >&2; exit 2 ;;
esac
case "$mode" in
    canary) artifact_label='canary' ;;
    kunci) artifact_label='kunci' ;;
    *) printf '%s\n' 'Mode harus canary atau kunci.' >&2; exit 2 ;;
esac

target_id=$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$target_host")
survivor_id=$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$survivor_host")
[ -n "$target_id" ] && [ -n "$survivor_id" ] || {
    printf '%s\n' 'Jalankan lab dengan overlay canary terlebih dahulu.' >&2
    exit 1
}
python3 -c 'import json,sys,urllib.request
with urllib.request.urlopen("http://127.0.0.1:8090/v1/dashboard", timeout=3) as response:
    data=json.load(response)
if not data.get("analysis", {}).get("auto_repair_enabled"):
    raise SystemExit("Playbook canary belum aktif. Jalankan compose.canary.yaml terlebih dahulu.")
if any(data.get("remediator", {}).get("by_host", {}).get(host, {}).get("status") != "ready" for host in ("server-a", "server-b")):
    raise SystemExit("Worker remediation belum sehat.")'
curl --fail --silent --show-error --request POST \
    "http://127.0.0.1:8090/v1/lab/recover/$target_host"
sleep 3
previous_run_id=$(python3 -c 'import json,urllib.request; d=json.load(urllib.request.urlopen("http://127.0.0.1:8090/v1/dashboard", timeout=3)); print((d.get("remediation") or {}).get("event_id", ""))')

if [ "$mode" = "kunci" ]; then
    printf 'Mengisengi kunci rahasia di %s (dicuri adalah seluruh isi file).\n' "$target_host"
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        python -c "from pathlib import Path; import time; Path('/data/etc/kunci1.dat').write_text('DEFNETT-LAB-THIEF-GRABBED ' + str(time.time()) + '\n', encoding='utf-8')"
else
    printf 'Menaruh canary teks aman di %s.\n' "$target_host"
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        python -c "from pathlib import Path; import time; Path('/data/DEFNETT-LAB-CANARY.txt').write_text('DEFNETT-LAB-MALWARE-CANARY ' + str(time.time()) + '\n', encoding='utf-8')"
fi
printf '\n%s\n' 'Menunggu isolasi, karantina, health check, dan rejoin:'
PREVIOUS_RUN_ID="$previous_run_id" python3 -c 'import json, os, time, urllib.request
with urllib.request.urlopen("http://127.0.0.1:8090/v1/dashboard", timeout=3) as response:
    initial = json.load(response)
delay = int(initial.get("analysis", {}).get("demo_repair_delay_seconds", 0))
deadline = time.time() + max(45, delay + 60)
while time.time() < deadline:
    with urllib.request.urlopen("http://127.0.0.1:8090/v1/dashboard", timeout=3) as response:
        data = json.load(response)
    run = data.get("remediation") or {}
    if run.get("event_id") != os.environ["PREVIOUS_RUN_ID"] and run.get("status") in {"REPAIRED", "FAILED"}:
        print(json.dumps({"status": run.get("status"), "detail": run.get("detail"), "quarantine_path": run.get("quarantine_path"), "steps": [step.get("stage") for step in run.get("steps", [])]}, ensure_ascii=False))
        if run.get("status") != "REPAIRED" or not run.get("quarantine_path"):
            raise SystemExit("Pemulihan otomatis gagal.")
        break
    time.sleep(1)
else:
    raise SystemExit("Pemulihan otomatis melewati batas waktu.")'

if [ "$mode" = "kunci" ]; then
    worker="remediator-$(printf '%s' "$target_host" | sed 's/^server-//')"
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$worker" \
        sh -c 'cmp -s /target/etc/kunci1.dat /master/kunci1.dat && cmp -s /target/etc/kunci2.dat /master/kunci2.dat'
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        sh -c 'grep -q "SECRET kunci1" /data/etc/kunci1.dat && grep -q "SECRET kunci2" /data/etc/kunci2.dat'
    printf 'Kunci dipulihkan byte-per-byte dari master di %s.\n' "$target_host"
else
    docker compose -f "$compose_file" -f "$canary_file" exec -T "$target_host" \
        python -c "from pathlib import Path; assert not Path('/data/DEFNETT-LAB-CANARY.txt').exists(), 'canary masih ada di /data'"
fi

printf '\n%s\n' 'Memastikan Server A dan Server B kembali melayani trafik:'
seen_a=0
seen_b=0
for i in 1 2 3 4; do
    response=$(curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8080/)
    printf 'Request %s: %s\n' "$i" "$(printf '%s' "$response" | head -n 1)"
    case "$response" in
        *"response from server-a"*) seen_a=1 ;;
        *"response from server-b"*) seen_b=1 ;;
        *) printf '%s\n' 'Request tidak cocok dengan backend yang diharapkan.' >&2; exit 1 ;;
    esac
done
[ "$seen_a" -eq 1 ] && [ "$seen_b" -eq 1 ] || {
    printf '%s\n' 'Rejoin check gagal: kedua backend belum terlihat.' >&2
    exit 1
}
[ "$target_id" = "$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$target_host")" ] || {
    printf 'Container %s berubah saat playbook; hasil uji tidak valid.\n' "$target_host" >&2
    exit 1
}
[ "$survivor_id" = "$(docker compose -f "$compose_file" -f "$canary_file" ps -q "$survivor_host")" ] || {
    printf '%s\n' 'Container server survivor berubah; host yang tidak diserang ikut tersentuh.' >&2
    exit 1
}

printf '\n%s\n' 'Memeriksa trafik sebelum, selama, dan setelah containment:'
TARGET_HOST="$target_host" SURVIVOR_HOST="$survivor_host" python3 - <<'PY'
import json, os, urllib.request

with urllib.request.urlopen("http://127.0.0.1:8090/v1/dashboard", timeout=3) as response:
    traffic = json.load(response).get("traffic") or {}
if not traffic.get("enabled"):
    raise SystemExit("Probe trafik nonaktif; set TRAFFIC_PROBE_ENABLED=true untuk pemeriksaan ini.")
windows = traffic["windows"]
for phase in ("before", "during", "after"):
    w = windows[phase]
    print(f"{phase:>6}: ok={w['ok']} fail={w['fail']} by_host={w['by_host']}")
target, survivor = os.environ["TARGET_HOST"], os.environ["SURVIVOR_HOST"]
if any(windows[phase]["fail"] for phase in windows):
    raise SystemExit("Ada request gagal selama containment; layanan tidak tetap tersedia.")
during = windows["during"]["by_host"]
if not during.get(survivor, 0) > during.get(target, 0):
    raise SystemExit("Selama containment, survivor harus menjawab lebih banyak daripada host target.")
PY

printf '\n%s\n' "Selesai: hanya $target_host yang dipulihkan; $survivor_host tidak diperbaiki dan kedua container tidak direstart."
