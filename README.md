# DEFNETT

Lab pertahanan siber dua server di balik load balancer. Agent memantau integritas file, collector menilai risiko, dan saat file penting diubah, server target dikeluarkan dari HAProxy, dipulihkan, lalu dimasukkan kembali, sementara situs tetap melayani lewat server lainnya.

Karya untuk Kartika Cyber Hackathon 2026, kategori **Penangkalan** (Automated Incident Response).

## Relevansi untuk pengamanan sistem satuan

- **Layanan tetap hidup.** Server yang diserang diisolasi tanpa memutus pengguna, selama ada server lain yang sehat.
- **Respons otomatis.** Isolasi, karantina, dan pemulihan berjalan tanpa menunggu keputusan operator.
- **Bukti terjaga.** File yang rusak dikarantina, dan event dicatat di SQLite dengan hash chain.
- **Bisa di jaringan tertutup.** Kode tim hanya memakai pustaka standar Python, ditambah HAProxy dan SQLite, tanpa layanan cloud.
- **Waktu respons terukur.** Setiap insiden mencatat waktu deteksi, isolasi, dan pulih.

Ini purwarupa lab. Penerapan di lingkungan satuan memerlukan pengujian lanjutan.

## Cara mencoba

Pilih salah satu:

- **Docker (satu komputer):** jalankan `sh lab/build.sh`, lalu buka dashboard di `http://127.0.0.1:8090/`.
- **Empat VM VirtualBox:** konfigurasi ada di [lab/vm](lab/vm); dashboard di `http://192.168.56.20:8090/`.
- **Tanpa menjalankan apa pun:** lihat bagian Tampilan di bawah dan video demo.

Setelah dashboard terbuka, pilih tab **Patrol**, pilih server dan jalur (SSH atau Web), lalu tekan **Serang!**.

Pengujian otomatis: `python3 -m unittest discover -s lab/tests`. Dokumen lengkap: [Dokumentasi Teknis](docs/DOKUMENTASI_TEKNIS.md) dan [Hasil Uji](docs/HASIL_UJI.md).

## Hasil uji

Diuji dengan enam insiden sungguhan di empat VM: 6 dari 6 pulih, dan 400 permintaan lewat load balancer semuanya berhasil. Deteksi paling lama 3,02 detik, isolasi paling lama 0,02 detik, dan pemulihan paling lama 1,55 detik di luar jeda demo. Jalur Docker juga lolos uji dari instalasi bersih.

## Materi submission

- Video demo: [isi tautan YouTube]
- Slide penjelasan: [isi tautan slide]

## Arsitektur

| VM | Alamat | Peran |
|---|---|---|
| Gateway | `192.168.56.10` | HAProxy, port 8080 |
| Server A | `192.168.56.11` | App, agent FIM, remediator |
| Server B | `192.168.56.12` | App, agent FIM, remediator |
| Collector | `192.168.56.20` | Collector dan dashboard, port 8090 |

## Tampilan

Overview:

![Overview](lab/screenshots/01-overview.png)

Patrol. Jumlah pintu tiap server mengikuti port yang benar-benar terbuka (`22 SSH`, `80 HTTP`, `8080 APP`, `8091 WORKER`):

![Patrol](lab/screenshots/02-patrol.png)

Tab File, menampilkan file system tiap server per folder:

![File system](lab/screenshots/03-file-system.png)

Tombol **Serang!** punya pilihan jalur **SSH** atau **Web**. Dengan jalur SSH, intruder masuk lewat pintu 22:

![Intruder masuk lewat SSH](lab/screenshots/04-serangan-ssh-masuk.png)

Setelah file kunci diubah, Server A keluar dari HAProxy dan trafik pindah ke Server B:

![Serangan di Patrol](lab/screenshots/04-serangan-patrol.png)

![Serangan di Overview](lab/screenshots/05-serangan-overview.png)

Setelah file dipulihkan dan health check lolos, Server A kembali ke rotasi:

![Pulih](lab/screenshots/06-pulih.png)

Dengan jalur Web, intruder masuk lewat pintu 80, dan Server B yang keluar dari rotasi:

![Intruder masuk lewat Web](lab/screenshots/09-serangan-web-masuk.png)

![Serangan web di Patrol](lab/screenshots/10-serangan-web-patrol.png)

## Situs yang dilayani

Kedua server melayani blog WordPress di port 80, dan HAProxy membagi trafik ke keduanya. Setiap halaman memuat lencana serta judul **SERVER A** atau **SERVER B**, sehingga server yang menjawab langsung terlihat.

![Blog di Server A](lab/screenshots/07-blog-server-a.png)

![Blog di Server B](lab/screenshots/08-blog-server-b.png)

Konfigurasi gateway ada di [lab/vm/gateway/haproxy.cfg](lab/vm/gateway/haproxy.cfg). WordPress 5.0 memerlukan satu perbaikan agar halaman daftar tulisan tampil di PHP 8, yaitu [lab/vm/fix-wp-php8-home.sh](lab/vm/fix-wp-php8-home.sh).

## Catatan keamanan

Lab ini sengaja dibuat rentan dan **hanya untuk jaringan lab yang terisolasi**.

- **Perangkat lunak lama:** blog memakai WordPress 5.0, versi lama yang memiliki kerentanan publik yang sudah diketahui. Versi itu dipilih karena tujuan lab ini adalah mengamati deteksi dan respons terhadap serangan, bukan menjaga situs tetap aman.
- **Data contoh:** `kunci1.dat` dan `kunci2.dat`, akun blog, dan seluruh isi `/data` adalah data buatan, bukan data nyata.
- **Jangan dipasang di jaringan publik:** jangan dibuka ke internet dan jangan diisi data pribadi. Jaringan antar VM memakai host-only, dan firewall tiap VM hanya mengizinkan lalu lintas yang diperlukan.
- **Skor risiko berbasis aturan:** penilaian di dashboard bukan model AI terlatih, dan tombol **Serang!** hanya mengubah file kunci demo di server lab.

## Komponen dan atribusi

Dibuat tim: agent FIM (`lab/agent.py`), collector (`lab/collector.py`), remediator (`lab/remediator.py`), aplikasi demo (`lab/app.py`), dan dashboard (`lab/dashboard`).

Pihak ketiga, dipakai sesuai lisensi masing-masing: HAProxy, WordPress 5.0, Python, SQLite, Docker, dan VirtualBox. [Tambahkan aset visual atau library lain jika ada.]

## Rencana pengembangan

Jika lolos ke babak selanjutnya, kami akan:

- **Membuat model ML untuk skor risiko**, agar penilaian lebih akurat daripada skor berbasis aturan yang dipakai sekarang.
- **Membatasi Polisi AI (agent FIM) ke izin read-only**, sehingga agent hanya bisa membaca dan memantau file.
- **Membatasi Satpam (remediator) ke izin execute dan write saja**, sehingga Satpam hanya menjalankan perbaikan dan menulis file pemulihan.

## Dokumentasi

Cara menjalankan dan detail teknis ada di [lab/README.md](lab/README.md). Konfigurasi VM ada di [lab/vm](lab/vm).

Proyek ini hanya untuk lab terisolasi. Berkas `kunci1.dat` dan `kunci2.dat` adalah data contoh, dan skor risiko berbasis aturan, bukan model AI terlatih.
