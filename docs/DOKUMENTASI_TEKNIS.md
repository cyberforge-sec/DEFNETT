# Dokumentasi Teknis DEFNETT

DEFNETT adalah purwarupa respons insiden otomatis untuk layanan dua server di balik load balancer. Saat file penting berubah, server target dikeluarkan dari rotasi, file dipulihkan, lalu server dimasukkan kembali setelah health check lolos. Selama itu server lain tetap melayani pengguna.

## Komponen

| Komponen | Berkas | Tugas |
|---|---|---|
| Agent | `lab/agent.py` | Memantau hash `/data`, port terbuka, log login, dan inventaris file system |
| Collector | `lab/collector.py` | Menerima event, menilai risiko, menjalankan playbook, melayani dashboard |
| Remediator | `lab/remediator.py` | Mengarantina file dan memulihkan kunci pada host-nya sendiri |
| Dashboard | `lab/dashboard` | Overview, Patrol, tab File, Playbook, dan Trafik |
| Gateway | HAProxy | Membagi trafik dan menjalankan perintah isolasi |

Kode buatan tim hanya memakai pustaka standar Python, sehingga dapat dipasang di jaringan tertutup tanpa mengunduh dependensi Python.

## Alur insiden

1. Agent melihat hash `etc/kunci1.dat` atau `etc/kunci2.dat` berubah.
2. Collector mencatat event ke rantai hash dan menilainya sebagai level 3.
3. Collector memastikan server lain sehat. Bila tidak, playbook berhenti dan server target tidak diubah.
4. Collector memerintahkan HAProxy mengeluarkan server target, lalu menunggu konfirmasi.
5. Remediator mengarantina file yang berubah dan memulihkan kunci dari salinan `/master`.
6. Hash hasil pemulihan diverifikasi, lalu HAProxy memeriksa kesehatan server.
7. Server kembali ke rotasi. Bila health check gagal, server tetap terisolasi.

## API utama

| Metode dan jalur | Fungsi | Token |
|---|---|---|
| `POST /v1/events` | Event integritas dari agent | Ya |
| `POST /v1/agent/heartbeat` | Heartbeat dan daftar port | Ya |
| `POST /api/patrol/events` | Event akses dan login | Ya |
| `POST /v1/patrol/snapshot`, `/v1/patrol/inventory` | Daftar file dan inventaris | Ya |
| `POST /v1/lab/attack/<host>?vector=ssh\|web` | Simulasi serangan demo | Tidak |
| `POST /v1/lab/recover/<host>` | Pemulihan manual oleh operator | Tidak |
| `GET /v1/dashboard` | Status lab dan riwayat insiden | Tidak |
| `GET /v1/evidence/verify` | Pemeriksaan rantai bukti | Tidak |

## Keamanan

- **Token antarkomponen:** agent, aplikasi, dan collector saling mengirim `LAB_API_TOKEN`. Remediator menolak permintaan tanpa token. Token disimpan di env layanan, bukan di repo.
- **Hak akses layanan:** semua layanan berjalan sebagai user `defnett` dengan sandbox systemd. Agent hanya punya akses tulis ke `/state`, jadi folder yang dipantau bersifat read-only baginya.
- **Pemisahan peran:** remediator tiap host hanya menerima perintah untuk host itu sendiri.
- **Jaringan:** VM berada di jaringan host-only, dan firewall tiap VM hanya mengizinkan lalu lintas yang diperlukan.

## Batasan

- Skor risiko berbasis aturan, belum model ML.
- Komunikasi antarkomponen memakai HTTP tanpa enkripsi.
- Dashboard dan endpoint `/v1/lab/*` belum punya login, jadi aksesnya bergantung pada firewall.
- Collector adalah satu titik kegagalan. Bila mati, pemantauan berhenti, tapi layanan tetap berjalan.
- Rantai hash mendeteksi perubahan baris, tapi belum ditanam ke sistem eksternal.
- Cakupan yang diuji adalah sistem IT berbasis Linux. Sistem OT belum diuji.

## Pemasangan

- **Docker:** `sh lab/build.sh`, lalu buka `http://127.0.0.1:8090/`.
- **VM:** konfigurasi tiap VM ada di `lab/vm`, dan pembaruan dipasang dengan `lab/vm/deploy-update.sh`.
- **Pengujian otomatis:** `python3 -m unittest discover -s lab/tests`.

Hasil pengujian di lab ada di [HASIL_UJI.md](HASIL_UJI.md).
