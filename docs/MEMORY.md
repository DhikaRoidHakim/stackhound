# MEMORY — Keputusan & Fakta Teknis StackHound

Berisi keputusan desain (`D-xxx`) beserta alasannya, dan fakta teknis (`F-xxx`) yang tidak terlihat dari kode. Entri baru ditambahkan di bawah; entri lama tidak dihapus. Jika ada keputusan yang dibatalkan, tandai **[DIGANTI oleh D-yyy]**.

## Keputusan

### D-001 — PRD v1.1.0 jadi acuan tunggal (2026-10-27)
PRD v1.0.0 dan Addendum NVD/OSV digabung menjadi `docs/StackHound_PRD_v1.1.docx`.
**Alasan:** di v1.0.0 kedua dokumen itu saling bertentangan, misalnya path cache dan peran NVD untuk Laravel.

### D-002 — Stack inti (2026-10-27)
Typer + Questionary + Rich, `httpx[http2]` async, BeautifulSoup4 + lxml, Pydantic v2, Jinja2, `platformdirs`, `packaging`, `cvss`. Untuk dev: pytest, pytest-asyncio, respx, ruff, mypy.
**Alasan:** banyak endpoint diperiksa sekaligus sehingga butuh async; `platformdirs` agar jalan di Windows; `cvss` karena OSV hanya memberi vector string.

### D-003 — Framework hanya di-query ke OSV, bukan NVD (2026-10-27)
NVD dipakai untuk infrastruktur saja (php, nginx, apache, openssl, iis).
**Alasan:** menghindari duplikasi CVE, dan nama package OSV lebih presisi daripada CPE framework yang belum tentu benar.

### D-004 — Redaksi evidence wajib & terpusat (2026-10-27)
Semua evidence melewati `core/redaction.py`. Body mentah dari target tidak pernah disimpan, termasuk di cache.
**Alasan:** laporan JSON/HTML sering menjadi artifact CI. Tanpa redaksi, tool ini justru akan membocorkan secret yang ditemukannya.

### D-005 — Baseline soft-404 untuk semua cek path (2026-10-27)
**Alasan:** SPA, catch-all route, dan WAF sering mengembalikan 200 untuk path apa pun, sehingga cek berdasarkan status code saja menghasilkan false positive massal.

### D-006 — Probe PATCH LRV-02 dijaga dengan OPTIONS (2026-10-27)
Probe default aktif, tapi hanya dikirim jika `Allow` dari `OPTIONS /` tidak memuat PATCH. Bisa dimatikan dengan `--no-method-probe`.
**Alasan:** dengan syarat itu router dijamin menolak request (405) sebelum handler berjalan, jadi tetap non-destruktif. Lihat F-004.

### D-007 — Header identitas tidak bisa dimatikan (2026-10-27)
`X-Security-Audit: StackHound/<versi>` selalu dikirim, walaupun User-Agent diganti.
**Alasan:** Blue Team harus selalu bisa mengenali trafik audit.

### D-008 — Otorisasi eksplisit (2026-10-27)
Mode interaktif menanyakan konfirmasi sekali per target per sesi. Mode non-interaktif wajib memakai `--authorized`; tanpa flag itu keluar dengan exit code 2 sebelum ada request apa pun.

### D-009 — Exit code (2026-10-27)
| Kode | Arti |
|---|---|
| 0 | OK |
| 1 | Ada temuan ≥ `--fail-on` |
| 2 | Usage error |
| 3 | Pre-flight gagal |
| 4 | Scan parsial |

Jika kode 1 dan 4 sama-sama berlaku, kode 1 yang dipakai.

### D-010 — Formula Security Grade (2026-10-27)
- Skor awal 100, dikurangi penalti: CRITICAL 40 / HIGH 20 / MEDIUM 8 / LOW 3 / INFO 0.
- Penalti dikalikan faktor confidence: HIGH 1,0 / MEDIUM 0,75 / LOW 0,25.
- Vulnerability dikelompokkan per komponen: penalti severity tertinggi + 1 per kerentanan tambahan (maksimal +10). Dependency dev × 0,5.
- Grade: A+ ≥ 97 (tanpa temuan MEDIUM ke atas), A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.
- Ada CRITICAL ber-confidence HIGH → otomatis F. Ada HIGH ber-confidence HIGH → maksimal C.

### D-011 — Bahasa (2026-10-27)
Kode dan komentar dalam bahasa Inggris. Output CLI dan laporan dalam bahasa Indonesia. Antarmuka bahasa Inggris masuk backlog.

### D-012 — Lokasi file pengguna (2026-10-27)
- Config: `platformdirs.user_config_dir("shound")/config.json`
- Cache: `platformdirs.user_cache_dir("shound")/cache.db` (SQLite WAL)

Keduanya menggantikan `~/.shound/` dari v1.0.0.

## Fakta teknis

- **F-001 — NVD `isVulnerable`.** Tanpa parameter ini, query `cpeName` juga mengembalikan CVE aplikasi lain yang hanya *berjalan di atas* komponen tersebut (misalnya ratusan aplikasi PHP). Hasil NVD juga harus di-paginate (`resultsPerPage` maksimal 2000, `startIndex`).
- **F-002 — NVD `cpeName` harus ada di CPE Dictionary.** Jika tidak ada, hasilnya kosong, dan itu bukan berarti aman. Cek dulu lewat `/rest/json/cpes/2.0`, fallback ke `virtualMatchString`.
- **F-003 — nginx punya dua vendor CPE**: `nginx:nginx` (CVE lama) dan `f5:nginx` (CVE baru). Query keduanya.
- **F-004 — Kenapa debug mode Laravel bocor lewat 405.** Laravel tidak punya view error 405 bawaan (hanya 401, 402, 403, 404, 419, 429, 500, 503). Karena itu `MethodNotAllowedHttpException` di debug mode dirender oleh Ignition. Untuk OPTIONS yang tidak punya route, router Laravel otomatis menjawab dengan header `Allow`.
- **F-005 — `XSRF-TOKEN` Laravel sengaja tidak HttpOnly** karena dibaca JavaScript (axios). Jangan dilaporkan di SH-02 untuk HttpOnly. Nama cookie ini juga dipakai Angular, jadi bobot fingerprint-nya kecil.
- **F-006 — OSV tidak memberi skor numerik.** `severity[].score` berisi vector CVSS. Fallback ke `database_specific.severity` (GHSA memakai `MODERATE` = MEDIUM).
- **F-007 — Satu advisory OSV bisa punya beberapa range per cabang** (8.x / 9.x / 10.x). `fixed_version` harus diambil dari interval yang memuat versi terdeteksi.
- **F-008 — Respons OSV `querybatch` hanya berisi ID**, dengan `next_page_token` per query. Detail diambil via `/v1/vulns/{id}` setelah ID dideduplikasi.
- **F-009 — Banner versi distro sering di-backport** (misalnya `Apache/2.4.41 (Ubuntu)`). CVE NVD dari banner yang memuat token distro diberi confidence LOW.
- **F-010 — Format lock file.** `composer.lock` punya `packages` dan `packages-dev`; versi berprefiks `v`; versi `dev-*` tidak bisa diaudit. `package-lock.json` v1 memakai `dependencies`, sedangkan v2/v3 memakai `packages` dengan key `node_modules/...`. `requirements.txt` hanya bisa diaudit untuk pin `==`.
- **F-011 — Pydantic v2:** `Optional[X]` tanpa default tetap wajib diisi.
- **F-012 — Batas rate NVD:** 5 request / 30 detik tanpa API key, 50 request / 30 detik dengan key.
