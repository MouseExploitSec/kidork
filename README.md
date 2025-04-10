# KIDORK
![Screenshot_1](https://github.com/MouseExploitSec/kidork/blob/main/foto.png)

> Tools pencari dork berbasis Google dengan fitur deteksi CMS dan celah SQLi otomatis. Cocok untuk pentester, bug hunter, atau edukasi keamanan web.

- Python 3.6 atau lebih baru
- `pip` (Python package installer)

## [+] FITUR-FITUR UTAMA

1. Google Dork Search
   - Menggunakan Google Custom Search API
   - Mendukung banyak dork sekaligus
   - Bisa atur jumlah hasil via argumen `-j`
2. SQL Injection Scanner
   - Opsi `--scan-sqli` untuk aktifkan scanner
   - Menggunakan payload dasar: `'`, `'--`, `' or '1'='1`
   - Mendeteksi error SQL dari berbagai DBMS (MySQL, PostgreSQL, Oracle, dll)
   - URL yang rentan akan disimpan ke `vuln.txt`
3. CMS Detector
   - Deteksi otomatis CMS populer:
     - WordPress
     - Joomla
     - Drupal
     - Shopify
     - PrestaShop
     - Magento
4. Simpan Hasil
   - Simpan semua hasil URL ke file (opsional dengan `--save hasil.txt`)
   - Simpan otomatis ke database SQLite `results.db`
   - Tabel: `hasil_dork` (url, vulnerable, cms, timestamp)
5. Asynchronous & Cepat
   - Menggunakan `asyncio` dan `aiohttp` untuk performa cepat
   - Pemrosesan banyak URL dilakukan secara paralel
6. CLI Warna-warni
   - Tampilan hasil interaktif dengan warna:
     - Biru = Info
     - Hijau = Sukses
     - Kuning = Warning
     - Merah = Error / VULN
       
## [+]OUTPUT FILE YANG DIHASILKAN

- hasil.txt      → Daftar URL hasil dork (jika opsi --save digunakan)
- vuln.txt       → URL rentan SQLi
- results.db     → Database SQLite berisi semua hasil

## Installation on Linux
  ```bash
sudo apt update
sudo apt install python3 python3-pip
git clone https://github.com/MouseExploitSec/kidork
cd kidork
cd kidork-msxsec
pip3 install -r requirements.txt
python kidork.py --help
```

## Installation on Termux
  ```bash
pkg update && pkg upgrade
pkg install python
git clone https://github.com/MouseExploitSec/kidork
cd kidork
cd kidork-msxsec
pip install -r requirements.txt
python kidork.py --help
```

## 📄 Lisensi

### Penjelasan:
- **Persyaratan**: Menyebutkan versi Python dan pip yang dibutuhkan.
- **Instalasi di Termux**: Menyediakan langkah-langkah untuk menginstal di perangkat Android menggunakan Termux.
- **Instalasi di Linux**: Memberikan instruksi untuk menginstal di sistem Linux berbasis Debian (Ubuntu/Debian).
- **Penggunaan**: Menjelaskan cara menjalankan alat serta beberapa opsi yang tersedia.
- **Lisensi**: Menyebutkan lisensi alat ini (CC BY-NC-ND 4.0).

Anda diperbolehkan menggunakan dan membagikan tools ini, namun **tidak diizinkan untuk mengubah atau menjualnya**.
(`https://github.com/MouseExploitSec/kidork`) dengan URL repositori yang sebenarnya.
Tools ini dilisensikan di bawah [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/deed.id).  

##
 AUTHOR & CREDIT

  ✦ Author : sam - msxsec
  
  ✦ GitHub : https://github.com/MouseExploitSec
