# Naskah Video DEFNETT: Atnan, Adiva, Qilah

Durasi sekitar 8 menit (batas rulebook 10 menit, unggah ke YouTube). Naskah ini mengikuti demo sungguhan di lab, bukan urutan slide. Bacakan teks dalam tanda kutip, sedangkan teks dalam kurung siku adalah petunjuk layar.

| Orang | Tugas |
|---|---|
| **Atnan** | Membuka video dan menjelaskan masalah serta manfaat |
| **Adiva** | Mengoperasikan demo di dashboard |
| **Qilah** | Menjelaskan hal teknis dan batasan, serta menutup video |

## Persiapan sebelum rekam

- Nyalakan empat VM, lalu buka `http://192.168.56.20:8090/` dan tekan `Cmd+Shift+R`.
- Pastikan Mode **AKTIF**, Server A dan B **UP**, dan LB **2/2**.
- Buka tiga tab: dashboard, blog `http://192.168.56.10:8080/`, dan terminal.
- Tutup jendela yang memuat password atau data pribadi, dan jangan tampilkan password saat login.
- Latihan sekali. Satu serangan butuh sekitar 30 detik sampai server pulih.
- Antarserangan, tunggu sekitar 25 detik sampai tombol **SERANG!** aktif kembali.

## 1. Pembuka (0:00–0:50)

[Kamera atau layar menampilkan dashboard Overview]

**Atnan:** "Halo, kami tim [nama tim] dari [instansi]. Saya Atnan, bersama Adiva dan Qilah. Karya kami DEFNETT, untuk kategori Penangkalan di Kartika Cyber Hackathon 2026."

**Atnan:** "Bayangkan server satuan diretas, tapi layanan harus tetap berjalan. Kalau server dimatikan, pengguna ikut terputus. Kalau menunggu operator, penyerang punya waktu. DEFNETT menjawab masalah itu dengan respons otomatis, dan kami akan langsung menunjukkannya."

## 2. Kondisi normal (0:50–2:00)

[Adiva membuka tab Overview]

**Adiva:** "Ini Overview. Kedua server UP, dan load balancer menunjukkan 2 dari 2. Semua angka ini dibaca dari HAProxy asli."

[Adiva membuka tab blog dan refresh beberapa kali]

**Adiva:** "Ini blog yang dilayani lab kami. Lihat lencana di kiri atas: kalau saya refresh, berganti antara Server A dan Server B. Artinya trafik memang dibagi dua."

[Adiva membuka tab Patrol]

**Qilah:** "Di tab Patrol, tiap server digambar sebagai ruangan. Kotak-kotak ini file di folder `/data`, yang hash-nya diperiksa agent setiap tiga detik. Pintu di bawah bukan hiasan: tiap pintu adalah port yang benar-benar terbuka, yaitu 22 SSH, 80 HTTP, 8080 aplikasi, dan 8091 worker."

[Adiva membuka sidebar tab File, lalu membuka folder `/etc`]

**Qilah:** "Di tab File, kita bisa menelusuri file system server dari dashboard. Isinya hanya daftar nama dan ukuran file, bukan isi file."

## 3. Serangan lewat SSH (2:00–4:10)

[Adiva kembali ke tab Events. Pilih Server A, jalur SSH]

**Adiva:** "Sekarang kita serang Server A lewat jalur SSH. Yang saya tekan ini bukan animasi."

[Adiva menekan SERANG!]

**Qilah:** "Jalur masuk intruder ini simulasi, jadi tidak ada eksploit sungguhan. Tapi setelah itu, sistem benar-benar menambah satu baris penanda ke file kunci di Server A."

[Intruder masuk lewat pintu 22]

**Adiva:** "Intruder masuk lewat pintu 22, sesuai jalur yang kita pilih."

[Tunggu status berubah]

**Adiva:** "Nah, Server A berubah menjadi DOWN, dan load balancer tinggal 1 dari 2. Kabel ke Server A putus, dan gerbangnya tertutup."

**Qilah:** "Ini yang terjadi di belakang layar. Agent melihat hash file berubah, collector memastikan Server B sehat, lalu memerintahkan HAProxy mengeluarkan Server A."

[Adiva pindah ke tab blog dan refresh beberapa kali]

**Adiva:** "Blognya tetap terbuka. Sekarang lencananya selalu Server B, jadi pengguna tidak merasakan gangguan."

[Adiva kembali ke Patrol. Buka tab Playbook di sidebar]

**Qilah:** "Di tab Playbook terlihat tahapannya. File yang diubah disimpan ke karantina sebagai bukti, lalu kuncinya dipulihkan dari salinan master."

[Tunggu sampai Server A UP]

**Adiva:** "Server A sudah kembali UP, dan load balancer 2 dari 2. Semua berjalan tanpa operator menyentuh server."

[Tunjuk tiga angka waktu dan baris Masuk di tab Playbook]

**Qilah:** "Setiap insiden punya catatan waktu: kapan terdeteksi, kapan terisolasi, dan kapan pulih. Baris ini juga mencatat dari IP dan port mana penyerang masuk."

[Tunjuk lencana Bukti utuh]

**Qilah:** "Lencana ini memeriksa rantai bukti. Kalau catatan event diubah, hasil pemeriksaannya berubah menjadi rusak."

## 4. Serangan lewat Web (4:10–5:10)

[Tunggu tombol SERANG! aktif. Pilih Server B, jalur Web]

**Adiva:** "Sekarang kita coba jalur Web di Server B."

[Adiva menekan SERANG!]

**Adiva:** "Kali ini intruder masuk lewat pintu 80. Server B yang keluar dari rotasi, dan Server A yang menjaga layanan."

[Tunggu status DOWN, lalu refresh blog sekali]

**Atnan:** "Jadi server mana pun yang diserang, layanan tetap hidup selama ada satu server lain yang sehat."

## 5. Login SSH sungguhan (5:10–6:00)

[Adiva membuka terminal dan memperlihatkan Patrol berdampingan. Jalankan perintah ini:]

```bash
ssh -o PubkeyAuthentication=no malas@192.168.56.11
```

**Qilah:** "Selain tombol tadi, agent juga membaca log login asli. Ini login SSH sungguhan ke Server A."

[Adiva salah memasukkan password sekali. Jangan tampilkan password yang benar]

**Adiva:** "Password salah: intruder berhenti di pintu 22 dengan tanda DENIED."

[Adiva memasukkan password yang benar]

**Adiva:** "Password benar: intruder masuk lewat pintu 22, lengkap dengan alamat IP-nya."

**Qilah:** "Login memakai SSH key kami anggap admin, jadi tidak muncul sebagai intruder. Ini hanya penanda di dashboard, dan tidak memicu isolasi."

## 6. Manfaat dan kejujuran batasan (6:00–7:10)

[Layar kembali ke Overview]

**Atnan:** "Untuk sistem satuan, ada empat manfaat. Layanan tetap berjalan saat satu server diamankan. Respons tidak menunggu operator. Bukti bisa diverifikasi. Dan DEFNETT berjalan tanpa cloud atau internet, jadi cocok untuk jaringan tertutup."

**Atnan:** "Kami mengujinya dengan enam insiden sungguhan. Enam-enamnya pulih, dan 400 permintaan ke blog semuanya berhasil. Deteksi paling lama sekitar 3 detik, isolasi paling lama 0,02 detik, dan pemulihan paling lama sekitar 1,5 detik di luar jeda demo."

**Qilah:** "Kami juga jujur soal batasannya. Skor risiko masih berbasis aturan, bukan model AI. Karakter Polisi AI di peta hanya nama visual untuk agent. Jalur masuk tombol Serang adalah simulasi, dan blog WordPress 5.0 sengaja versi lama, jadi lab ini hanya untuk jaringan terisolasi."

## 7. Rencana dan penutup (7:10–8:00)

**Qilah:** "Jika lolos ke babak selanjutnya, kami akan membuat model ML agar skor risiko lebih akurat. Polisi AI akan dibatasi ke izin read-only, dan Satpam hanya punya izin execute dan write."

**Atnan:** "DEFNETT: server diserang, layanan tetap hidup. Kode dan dokumentasi ada di github.com/BlueSecc/DEFNETT. Terima kasih."

## Catatan rekaman

- **Bagian tunggu:** boleh dipercepat saat editing, tapi tulis keterangan "dipercepat" di layar.
- **Jeda demo:** kalau ditanya kenapa tertahan 15 detik, jawab bahwa jeda itu sengaja dipasang agar isolasi terlihat.
- **Jangan tunjukkan** password, alamat email, atau data pribadi.
- **Deskripsi YouTube:** isi link repo dan satu paragraf cara menjalankan lab.
- **Bagian 5 perlu latihan:** login SSH sungguhan sudah tertangkap datanya, tapi tampilannya di peta harus dicek dulu saat latihan. Kalau intruder tidak muncul, hapus bagian ini.
