# Hasil Uji DEFNETT

Diuji pada 2 November 2026 di empat VM VirtualBox dengan HAProxy asli. Setiap uji memicu insiden sungguhan: file kunci diubah, server keluar dari rotasi HAProxy, file dipulihkan, lalu server kembali setelah health check.

## Ringkasan

| Ukuran | Hasil |
|---|---|
| Insiden pulih sampai tuntas | 6 dari 6 |
| Permintaan blog lewat load balancer | 400, semuanya HTTP 200 |
| Dijawab Server A / Server B | 185 / 215 |
| Waktu deteksi | 0,29 sampai 3,02 detik, median 1,69 detik |
| Waktu isolasi setelah deteksi | 0,01 sampai 0,02 detik |
| Waktu pulih tanpa jeda demo | 0,53 sampai 1,55 detik, median 1,04 detik |
| Waktu pulih dengan jeda demo 15 detik | 15,53 sampai 16,55 detik |
| Verifikasi rantai bukti | Utuh, 3.103 event |

Enam insiden terdiri dari tiga di Server A dan tiga di Server B, memakai jalur SSH dan Web bergantian. Permintaan dikirim terus-menerus ke blog, sekitar tiga kali per detik.

## Cara membaca angka

- **Deteksi** dihitung dari waktu file berubah sampai agent melihatnya. Agent memeriksa tiap 3 detik, jadi batas atasnya sekitar 3 detik.
- **Isolasi** dihitung dari insiden tercatat sampai HAProxy mengonfirmasi server keluar rotasi.
- **Pulih** dihitung dari insiden tercatat sampai HAProxy melaporkan server `UP` penuh. Jeda demo 15 detik sengaja dipasang agar isolasi terlihat, dan tidak termasuk kerja sistem.
- Jalur masuk SSH atau Web pada uji ini adalah simulasi. Perubahan file, deteksi, isolasi, dan pemulihan berjalan sungguhan.

## Pemeriksaan lain

| Pemeriksaan | Hasil |
|---|---|
| Heartbeat ke collector tanpa token | Ditolak 401 |
| Perintah perbaikan ke remediator tanpa token | Ditolak 401 |
| Login SSH dengan password | Tertangkap sebagai event port 22 |
| Login SSH salah password | Tertangkap sebagai event ditolak |
| Port dilaporkan agent | 22, 80, 8080, 8091, sesuai yang terbuka dari luar |
| Pengujian otomatis (`lab/tests`) | 10 lolos |

Pengujian otomatis mencakup pembacaan log login, rotasi log, deteksi manipulasi bukti, event bersamaan, perhitungan waktu, dan penolakan token.

## Temuan saat pengujian

Pengujian mengungkap dua masalah yang sudah diperbaiki sebelum angka di atas diambil:

- Server sempat dianggap sehat saat HAProxy masih berstatus `UP 1/2`. Sekarang hanya status `UP` penuh yang lolos.
- Rantai hash berisiko bercabang saat dua agent mengirim event bersamaan. Sekarang penulisan event dikunci.

## Uji jalur Docker

Jalur `sh lab/build.sh` diuji dari instalasi bersih, memakai project Docker dan volume baru, di satu komputer. Langkah ini sama dengan yang dijalankan pembaca repo.

| Ukuran | Hasil |
|---|---|
| Build dan seed data | Berhasil, mode `ACTIVE_LAB`, Server A dan B `UP` |
| Insiden lewat API | 2 dari 2 pulih, 149 permintaan semuanya HTTP 200 |
| Dijawab Server A / Server B | 73 / 76 |
| Tombol **Serang!** di browser | Server keluar rotasi, load balancer `1/2`, lalu kembali `UP` |
| Waktu pulih tanpa jeda demo | 0,53 sampai 1,55 detik |
| Error JavaScript di dashboard | 0 |
| Verifikasi rantai bukti | Utuh, 117 event, semuanya terverifikasi penuh |

Docker berjalan dengan aplikasi demo, bukan WordPress, dan peta hanya menampilkan satu pintu. Jalur masuk yang dipilih tetap tercatat di tab Playbook.

## Belum diuji

- Login web `wp-login.php` sungguhan.
- Sistem OT dan beban trafik tinggi.
- 3.080 event lama di lab VM hanya terverifikasi tautan rantainya, karena isi lengkap baru disimpan setelah fitur ini ada. Event yang lebih baru terverifikasi penuh.
