# DEFNETT Lab

Lab ini mengimplementasikan dua server aplikasi dalam container, HAProxy, dua agent pemantau file, collector, worker remediation terpisah, karantina artefak, dan dashboard. Collector menyimpan event serta tahapan playbook di SQLite dengan hash chain.

Agent hanya memantau isi `/data` pada masing-masing server, bukan seluruh filesystem. Hash dipindai setiap tiga detik. Skor risiko dan verdict merupakan aturan deterministik, bukan classifier atau LLM terlatih. Mode normal memakai `DRY_RUN`; overlay canary mengaktifkan satu playbook terbatas.

## Jalankan

Dari root proyek:

```sh
docker compose -f lab/compose.yaml config
docker compose -f lab/compose.yaml up -d --build
docker compose -f lab/compose.yaml ps
```

Docker Engine harus sudah aktif. Aplikasi tersedia hanya pada komputer lokal:

- Layanan di belakang HAProxy: `http://127.0.0.1:8080/`
- Dashboard patroli dan analisis lab: `http://127.0.0.1:8090/`
- Health collector: `http://127.0.0.1:8090/healthz`
- Event dan keputusan: `http://127.0.0.1:8090/v1/events`
- Ringkasan dashboard (status backend, heartbeat agent, keputusan): `http://127.0.0.1:8090/v1/dashboard`
- Ringkasan jumlah event: `http://127.0.0.1:8090/v1/summary`

Perintah dasar di atas menjalankan collector dalam `DRY_RUN`. Untuk menjalankan demo lengkap, termasuk data contoh, playbook otomatis, dan tombol **Serang!**, pakai satu perintah ini:

```sh
sh lab/build.sh
```

Di Docker, agent berjalan di container terpisah dari server, jadi port tidak terbaca dan peta menampilkan satu pintu bawaan. Jalur SSH atau Web yang dipilih tetap tercatat di tab Playbook. Empat pintu dan blog WordPress hanya ada pada lab VM di `lab/vm`.

Dashboard menampilkan kesiapan worker dan tahapan setiap pemulihan. Overlay demo menahan tahap perbaikan selama 15 detik (`DEMO_REPAIR_DELAY_SECONDS`) agar isolasi terlihat. Hitung mundurnya tampil di dashboard saat server terisolasi; setelah jeda, artefak canary dikarantina, health check dijalankan, lalu Server A aktif kembali jika sehat. Jeda ini hanya untuk memperlihatkan alur demo, dan dashboard melaporkan waktu pulih tanpa jeda tersebut.

Dashboard memiliki tab **Patrol**. Peta Canvas 2D menyusun file dari snapshot hash agent ke ruang per server, menampilkan agent patroli, aktor berdasarkan IP, event akses, severity, dan detail hash. Snapshot hanya mengirim path relatif dan SHA-256, bukan isi file. Agent memakai `WATCH_ROOT` sebagai konfigurasi folder yang dipantau.

- Snapshot patrol: `GET /api/patrol/state`
- Event live: `GET /api/patrol/stream` (SSE)
- Ingest event akses: `POST /api/patrol/events`
- Snapshot hash agent: `POST /v1/patrol/snapshot`

### Animasi insiden (tab Patrol)

Tab Patrol sekarang memainkan cerita insiden dengan karakter game:

1. **Maling masuk.** Event serangan (request ke app atau event FIM non-safe dari agent) memunculkan maling yang berjalan lewat jalan, masuk pintu server, lalu beraksi di file: mengintip (read), membawa kabur (download), merusak (modify), menghapus (delete), atau menanam malware (file baru). Polisi (agent AI) mengejar dan memberi peringatan.
2. **Isolasi.** Saat playbook masuk `ISOLATING`, gerbang server turun dan kabel ke HAProxy putus (percikan + label PUTUS). Maling terjebak di dalam. Status HAProxy `MAINT` tanpa playbook juga ditampilkan sebagai server terisolasi.
3. **Maintenance (`REPAIRING`).** Satpam menempelkan badge dan masuk, maling mencoba kabur, polisi menembak sampai maling KO. Satpam lalu memperbaiki file dengan bar progres yang mengikuti hitung mundur demo 75 detik.
4. **Verifikasi dan rejoin.** Satpam memeriksa file satu per satu (tanda centang), kabel tersambung kembali, gerbang dibuka, server kembali ONLINE, dan maling diamankan.

Urutan visual mengikuti tahap asli dari `/v1/dashboard`; tiap tahap punya durasi tayang minimum agar tahap singkat tetap terlihat. Membuka dashboard di tengah insiden langsung menampilkan keadaan terakhir.

Tombol **Serang!** menjalankan insiden sungguhan, bukan animasi: `POST /v1/lab/attack/<host>` meminta worker host target menambah satu baris penanda ke `etc/kunci1.dat`. Agent mendeteksi perubahan itu, lalu playbook mengeluarkan server dari HAProxy (`disable server`), mengarantina file, memulihkannya dari `/master`, dan memasukkan server kembali setelah health check lolos. Status di dashboard dibaca dari HAProxy; `MAINT` ditampilkan sebagai `DOWN`. Pilihan **SSH / Web** di sebelahnya menentukan pintu yang dilewati intruder di peta (`?vector=ssh` atau `?vector=web`); jalur masuknya simulasi, tidak ada serangan nyata ke SSH atau WordPress. Tombol ini butuh `ENABLE_LAB_AUTOREPAIR=true` di collector dan `LAB_ATTACK_SIMULATION=true` di remediator, dan ditolak bila server lain tidak `UP`. Pasang di VM dengan `lab/vm/deploy-real-attack.sh`. Server yang tersangkut terisolasi dipulihkan dengan `POST /v1/lab/recover/<host>`.

Jumlah pintu tiap server mengikuti port TCP yang terbuka. Agent membaca `/proc/net/tcp` dan melaporkannya lewat heartbeat, jadi port yang hanya di loopback (misalnya MariaDB) tidak menjadi pintu, dan peta menampilkan paling banyak 6 pintu. Bila `AUTH_LOG` dan `WEB_LOG` diisi, agent juga membaca log login: login SSH berhasil dan login `wp-login.php` berhasil membuat intruder masuk lewat pintu port itu, sedangkan login gagal berhenti di pintu dengan tanda DENIED. Login SSH memakai kunci dianggap admin dan tidak ditampilkan; atur lewat `TRUSTED_SSH_METHODS`. Pasang di VM dengan `lab/vm/deploy-port-doors.sh`.

Pilih **Patrol → Mulai demo** untuk menghasilkan dua aktor sintetis dengan aksi berbeda. Simulator ini hanya berjalan pada browser dan tidak menulis file atau mengirim event palsu ke database. Event live berasal dari request ke app (`/` atau `/files/<path>`) serta event integritas agent. App hanya menyajikan file relatif yang terdaftar di `PATROL_PUBLIC_FILES` (default `index.txt`); file lain, file sensitif, dan metode tulis ditolak serta dicatat sebagai event. `WATCH_ROOT` pada tiap agent menentukan folder yang dipatroli. Analisis severity tetap berbasis aturan, bukan model AI terlatih.

## Simulasi containment yang aman

Dua playbook otomatis tersedia setelah overlay canary aktif:

1. **Mode canary** — agent menandai `DEFNETT-LAB-CANARY.txt` dari Insight isi; playbook mengisolasi host, mengkarantina canary, dan mengaktifkan kembali host.
2. **Mode kunci** — FIM melihat isi `etc/kunci1.dat`/`etc/kunci2.dat` berubah (dicuri/diubah); playbook mengisolasi host, worker mengkarantina kunci tampered sebagai bukti ke `/quarantine`, memulihkan **kedua** kunci byte-per-byte dari salinan master di volume `/master` (disemaikan dari `/data` saat worker start, hanya jika `/master` kosong), lalu host kembali aktif. Kunci yang masih asli tidak disentuh. Pemicu kunci hanya `file_modified` supaya proses karantina/pemulihan itu sendiri tidak memicu playbook berulang.

```sh
sh lab/test-containment.sh server-a canary   # default
sh lab/test-containment.sh server-a kunci    # Playbook kunci
```

Keduanya menunggu status `REPAIRED`, menguji trafik sebelum/selama/sesudah, dan memastikan konstruk kembali sehat.

Playbook memilih host dari event. Setiap server memiliki worker dan volume karantina sendiri. Untuk event Server A, hanya worker A yang dapat menulis volume A; Server B hanya bertugas menjaga layanan tetap tersedia. Aturan yang sama berlaku sebaliknya untuk event Server B. Sekarang ada dua marker: string `DEFNETT-LAB-MALWARE-CANARY` di `/data/DEFNETT-LAB-CANARY.txt`, atau isi kunci `etc/kunci1.dat`/`etc/kunci2.dat` yang berubah. Playbook kemudian:

1. Memastikan backend survivor sehat.
2. Mengeluarkan hanya host target dari rotasi HAProxy.
3. Dashboard menampilkan jeda demo saat host tetap terisolasi. Setelah jeda, worker host target mengarantina file canary terverifikasi ke volume terpisah.
4. HAProxy menjalankan health check dan mengaktifkan kembali hanya host target jika sehat.

Script default menguji Server A. Untuk menguji Server B sebagai host target:

```sh
sh lab/test-containment.sh server-b
```

Script menunggu status `REPAIRED`, memeriksa file sudah hilang dari `/data`, memastikan request kembali mencapai Server A dan B, dan memastikan ID container kedua server tidak berubah. Jika worker, karantina, atau health check gagal, sistem menjaga host target tetap diisolasi dan dashboard mencatat penyebabnya.

Ini hanya membersihkan satu artefak canary lab pada path tetap. Worker memeriksa tipe file, ukuran, dan isi marker sebelum memindahkannya serta memverifikasi SHA-256 salinan. Ini bukan antivirus, bukan perbaikan OS, dan tidak mendeteksi atau menghapus malware sungguhan. Tidak ada file lain yang disentuh.

Jika perlu mengaktifkan kembali backend secara manual setelah pemeriksaan operator:

```sh
curl --fail --request POST http://127.0.0.1:8090/v1/lab/recover/server-a
# Ganti server-a dengan server-b untuk memulihkan Server B.
```

API runtime HAProxy hanya tersedia di network kontrol internal. Worker remediation hanya berbagi network kontrol internal dengan collector dan memiliki akses tulis ke volume Server A serta volume karantina. Port worker tidak dipublikasikan ke host. Overlay canary mengaktifkan playbook khusus untuk file dan marker tetap di atas.

## Trafik sebelum, selama, setelah containment

Collector menjalankan probe kecil: satu `GET /healthz` per detik lewat HAProxy (`http://haproxy:8080/healthz`), lalu mencatat sukses/gagal dan backend yang menjawab (header `X-DEFNETT-Host`). Probe memakai `/healthz`, jadi tidak membuat event patrol atau aktor di peta. Hitungan dibagi tiga fase mengikuti playbook:

- **Sebelum:** sejak collector hidup (atau sejak pemulihan sebelumnya) sampai `ISOLATED`.
- **Selama:** dari `ISOLATED` sampai `REJOINING` selesai; host target sudah keluar dari rotasi.
- **Setelah:** mulai `REPAIRED`.

Hasil ada di `/v1/dashboard` pada kunci `traffic` dan di dashboard bagian "Request lewat HAProxy". Hitungan disimpan di memori collector, jadi reset saat collector restart. Nonaktifkan dengan `TRAFFIC_PROBE_ENABLED=false`; atur `TRAFFIC_PROBE_URL` dan `TRAFFIC_PROBE_INTERVAL` bila perlu.

## Inventaris file system di dashboard

Tab **File** di sidebar menampilkan isi file system tiap server per folder, bukan hanya `/data`. Agent memindai `INVENTORY_ROOT` setiap `INVENTORY_SECONDS` (default 300 detik) dan mengirim nama, jenis, ukuran, dan waktu ubah ke `/v1/patrol/inventory`. Dashboard membaca satu folder per klik lewat `/api/patrol/fs?host=server-a&path=/etc`.

- Inventaris hanya berisi metadata, tanpa hash dan tanpa isi file.
- Deteksi perubahan, alert, dan hewan patroli di kanvas tetap memakai `WATCH_ROOT`, yaitu `/data`.
- `/proc`, `/sys`, `/dev`, dan `/run` tampil sebagai virtual dan tidak dipindai.
- Di VM, `INVENTORY_ROOT=/`. Bila tidak diatur, nilainya mengikuti `WATCH_ROOT`, sehingga lab Docker hanya menampilkan `/watched`.
- Pasang di VM dengan `lab/vm/deploy-inventory.sh`, yang menyimpan file lama sebagai `*.bak-<waktu>`.

## Struktur /data: pohon ala Linux

Isi `/data` tiap server tidak flat. Script `lab/seed-fs.sh` menata ±22 direktori dan 56 file per host menyerupai pohon Linux (`bin`, `boot/grub`, `etc`, `home/kartika/notes`, `home/dima`, `opt/defnett`, `root`, `srv`, `usr`, `var/log`, `var/lib/defnett`). Jalankan dari root repo:

```sh
docker exec -i lab-server-a-1 sh -s server-a < lab/seed-fs.sh
docker exec -i lab-server-b-1 sh -s server-b < lab/seed-fs.sh
docker compose -f lab/compose.yaml -f lab/compose.canary.yaml restart agent-a agent-b
```

Aturan yang tetap berlaku:

- `index.txt` tetap di akar karena app menyajikan `/` ke file itu.
- Hanya path yang terdaftar di `PATROL_PUBLIC_FILES` (index, beberapa config distro, dan catatan di `home/kartika/...`) yang bisa dibaca lewat HAProxy; sisanya ditolak 403 dan dicatat sebagai event denied.
- `etc/kunci1.dat` dan `etc/kunci2.dat` adalah kunci rahasia: sengaja tidak didaftarkan sehingga selalu ditolak (di peta muncul sebagai ikon kunci emas dan menjadi target animasi "Serang!").
- `DEFNETT-LAB-CANARY.txt` harus tetap di akar `/data` karena playbook canary dan worker memakai jalur tetap itu. Restart agent setelah seed ulang agar baseline FIM segar tanpa event palsu.

## Demo perubahan file

```sh
sh lab/demo.sh
```

Agent akan mendeteksi perubahan `etc/new-config.txt` pada Server A dan mengirim event ke collector. Respons contoh tetap `DRY_RUN`; endpoint layanan tetap berjalan melalui HAProxy.

## Waktu respons, jalur masuk, dan rantai bukti

Tab **Playbook** menampilkan tiga angka yang dihitung dari stempel waktu insiden: waktu deteksi, waktu isolasi, dan waktu pulih tanpa jeda demo. Bila ada login berhasil di host yang sama dalam 10 menit terakhir, insiden mencatat IP dan port masuknya.

`GET /v1/evidence/verify` memeriksa seluruh rantai event, dan hasilnya tampil sebagai lencana **Bukti utuh**. Hash mendeteksi perubahan pada baris yang tersimpan, tapi rantai ini belum ditanam ke sistem eksternal, sehingga penyerang yang menguasai database masih bisa menulis ulang seluruh rantai.

## Autentikasi antarkomponen

Bila `LAB_API_TOKEN` diisi, collector dan remediator menolak permintaan mesin tanpa token yang cocok. Token dibaca dari env masing-masing layanan dan tidak disimpan di repo. Lab Docker tidak mengaktifkannya karena jaringannya internal. Dashboard belum punya login, jadi port 8090 harus dibatasi firewall.

## Pengujian otomatis

```sh
python3 -m unittest discover -s lab/tests
```

## Skrip utilitas

| Skrip | Fungsi |
|---|---|
| `sh lab/build.sh` | Bangun image, hidupkan lab lengkap, isi data contoh, dan siapkan salinan master kunci dalam satu perintah. |
| `sh lab/demo.sh` | Simulasi operator: ubah `etc/new-config.txt`, lalu lihat event/hash chain di collector. |
| `sh lab/attack.sh` | Simulasi pencuri lewat HAProxy: mengintip file publik, menebak nama sensitif, lalu mencoba `etc/kunci1.dat`/`etc/kunci2.dat` termasuk `?download=1` — setiap percobaan ditolak 403 dan muncul sebagai event denied (animasi pencuri di Patrol bergolak). |
| `sh lab/test-containment.sh` | Uji playbook penuh: canary → isolasi → karantina → verifikasi → rejoin + asersi trafik sebelum/selama/sesudah. |
| `sh lab/seed-fs.sh` (via `docker exec -i`) | Seed ulang pohon `/data` ala Linux; lihat bagian "Struktur /data" di atas. |

## Lihat log dan matikan lab

```sh
docker compose -f lab/compose.yaml logs -f
docker compose -f lab/compose.yaml down
```

`down` mempertahankan named volumes. Untuk menghapus seluruh data baseline dan bukti lab:

```sh
docker compose -f lab/compose.yaml down -v
```

Perintah terakhir menghapus data volume lab secara permanen.

## Dashboard dan batas purwarupa

Dashboard menampilkan heartbeat agent, status tiap worker, server yang menjadi target perbaikan, server survivor yang tetap berjalan, daftar event dan hash, serta tahapan `deteksi -> isolasi -> karantina -> verifikasi -> rejoin`. Worker hanya dapat menulis volume host pasangannya. Peta node adalah visualisasi alur layanan, bukan representasi neuron atau model AI sungguhan. Analisis yang berjalan adalah FIM dan aturan canary deterministik.

- Pemantauan polling membaca file di `/data`; belum menggunakan Wazuh agent atau memantau file sistem host.
- SQLite dan hash chain membantu demonstrasi audit, tetapi bukan penyimpanan bukti tahan manipulasi produksi.
- Collector menggabungkan ingestion, normalisasi minimal, penyimpanan, trajectory, scoring, dan policy dalam satu proses agar irisan end-to-end mudah dijalankan.
- Belum ada model ML, classifier terkalibrasi, atau isolasi jaringan container penuh. Isolasi lab mengeluarkan backend dari rotasi HAProxy.
- Pemulihan otomatis terbatas pada file canary dan dua file kunci lab pada host yang terdeteksi. Kasus selain itu gagal tertutup dan perlu pemeriksaan operator.
- Network Compose untuk layanan, telemetri, kontrol HAProxy, dan remediation dibuat terpisah/internal. HAProxy dan collector saja yang mempublikasikan port ke `127.0.0.1`.
