# Target uji Docker

> **Peringatan:** target Laravel di sini sengaja dibuat rentan (`.env`, `.git`, log, dan Telescope terbuka). Port hanya di-bind ke `127.0.0.1`; jangan diubah dan jangan di-deploy ke mana pun.

| Service | URL | Isi |
|---|---|---|
| `laravel12-debug` | http://127.0.0.1:8081 | Laravel 12, `APP_DEBUG=true`, `APP_ENV=local`, Telescope terbuka. Halaman error memakai renderer bawaan Laravel ≥ 11. |
| `laravel10-ignition` | http://127.0.0.1:8082 | Sama seperti di atas, tapi Laravel 10 dengan halaman error Ignition. |
| `spa-catchall` | http://127.0.0.1:8083 | Semua path mengembalikan `index.html` dengan status 200 (soft-404); kontrol negatif untuk false positive cek path. Selain itu sengaja memantulkan `Origin` apa pun (termasuk `null`) bersama `Allow-Credentials: true` untuk menguji SH-03. |
| `clean` | http://127.0.0.1:8084 | Situs statis dengan header keamanan lengkap; dotfile dan path tak dikenal mengembalikan 404. Audit header/cookie/CORS harus menghasilkan **nol temuan**. |

## Miskonfigurasi pada target Laravel

Web root diarahkan ke root proyek, bukan ke `/public`. File `.htaccess` di root meneruskan path yang tidak ada ke `public/` (pola shared hosting). Akibatnya semua file asli bisa diunduh:

- `/.env` dan `/.env.backup`
- `/.git/HEAD` dan `/.git/config` (URL remote berisi token palsu)
- `/storage/logs/laravel.log`
- `/composer.json` dan `/composer.lock`
- `/telescope`

Semua secret di target adalah **palsu** (lihat `laravel-debug/configure.sh`). Daftar yang sama dipakai di `FAKE_SECRETS` pada `tests/integration/test_targets.py`, untuk memastikan tidak ada secret yang lolos redaksi.

## Pemakaian

```bash
docker compose -f tests/targets/docker-compose.yml up -d --build
.venv/Scripts/python -m pytest -m targets
docker compose -f tests/targets/docker-compose.yml down
```

Test bertanda `targets` tidak ikut dijalankan oleh `pytest` biasa. Kalau container belum jalan, test-nya otomatis di-skip.
