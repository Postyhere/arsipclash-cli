# ArsipClash CLI

Konverter link **VMess / VLESS / Trojan** menjadi konfigurasi **Clash/BFR** langsung di Termux atau Python CLI.  
Hasil langsung ditampilkan di terminal (tidak menyimpan file).

## Instalasi

1. Clone repo:
```bash
git clone https://github.com/Postyhere/arsipclash-cli.git
cd arsipclash-cli
```

2. (Jika belum terpasang) install PyYAML (opsional, saat ini kode tidak perlu YAML library):
```bash
pip install pyyaml
```

## Penggunaan
```bash
python3 main.py
```
- Paste satu atau beberapa link (vmess://, vless://, trojan://).
- Tekan Enter setelah setiap link.
- Kosongkan input (tekan Enter) untuk selesai dan langsung muncul hasil konversi di terminal.

---
Dibuat oleh Postyhere
