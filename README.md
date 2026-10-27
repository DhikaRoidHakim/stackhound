# StackHound (`shound`)

**Framework-Based Security Configuration & CVE Auditor** — CLI Python untuk mengaudit aplikasi web secara **non-intrusive**: tanpa eksploitasi, tanpa brute-force, hanya membaca respons HTTP.

```
===================================================================
   _____ __             __   __  __                      __
  / ___// /_____ ______/ /__/ / / /___  __  ______  ____/ /
  \__ \/ __/ __ `/ ___/ //_/ /_/ / __ \/ / / / __ \/ __  /
 ___/ / /_/ /_/ / /__/ ,< / __  / /_/ / /_/ / / / / /_/ /
/____/\__/\__,_/\___/_/|_/_/ /_/\____/\__,_/_/ /_/\__,_/
  Framework-Based Security Configuration & CVE Auditor
===================================================================
```

> [!WARNING]
> **Gunakan hanya pada server/aplikasi milik sendiri atau yang memiliki izin audit resmi.**
> Memindai sistem tanpa izin dapat melanggar hukum (misalnya UU ITE).

> [!NOTE]
> **Status: pre-alpha (v0.1.0).** Fondasi sudah selesai. CLI dan menu interaktif sudah bisa dipakai untuk validasi input, otorisasi, dan `shound config`. Mode audit (`recon`, `audit`, `cve`, `deps`, `scan`) masih dibangun dan untuk sementara mengembalikan pesan "belum tersedia" (exit code 2). Lihat [Roadmap](#roadmap).

## Kenapa StackHound?

Banyak celah di aplikasi production bukan berasal dari zero-day, melainkan dari kesalahan konfigurasi dasar dan library yang usang, misalnya:

- `APP_DEBUG=true` di Laravel,
- file `.env` atau folder `.git` yang bisa diunduh,
- security header yang absen.

StackHound menggabungkan pemeriksaan-pemeriksaan itu dalam **satu laporan** dengan **satu Security Grade (A+ – F)** dan **langkah perbaikan spesifik per framework**.

Ada dua mode:

| Mode | Yang dilakukan |
|---|---|
| **Black-box** (target URL) | Fingerprint tech stack, cek security header/cookie/CORS/TLS, cek misconfiguration per framework, korelasi versi ke CVE (OSV.dev + NVD). |
| **White-box** (lock file lokal) | Audit `composer.lock`, `package-lock.json`, `requirements.txt` terhadap OSV.dev. |

## Prinsip keamanan

- **Non-destruktif.** Hanya `GET`, `HEAD`, dan `OPTIONS`. Satu-satunya pengecualian adalah probe `PATCH` tanpa body untuk deteksi debug mode. Probe itu hanya dikirim jika `OPTIONS` membuktikan server pasti menolaknya, dan bisa dimatikan dengan `--no-method-probe`.
- **Ramah server.** Rate limit global (default 5 request/detik). Tool mundur otomatis saat server membalas `429`/`503`, dan body respons dibatasi 1 MiB.
- **Mudah dikenali.** Setiap request membawa header `X-Security-Audit: StackHound/<versi>`, walaupun User-Agent diganti. Blue Team selalu bisa mengenali trafik audit di `access.log`.
- **Tidak membocorkan secret.** Secret yang ditemukan (nilai `.env`, kredensial di URL `.git/config`, token) **diredaksi** sebelum masuk laporan, log, atau cache. Isi file log target tidak pernah disimpan.
- **Tidak keluar dari target.** Redirect hanya diikuti di host yang sama.
- **Bukti, bukan tebakan.** Cek eksposur file wajib mencocokkan signature konten dan dibandingkan dengan baseline soft-404, sehingga server yang membalas `200` untuk semua path tidak menghasilkan false positive.

## Rencana pemakaian

> Perintah dan opsinya sudah terdaftar dan divalidasi, tapi mode audit belum menjalankan pemeriksaan. Spesifikasi lengkap ada di PRD (§2.2).
> Menu interaktif (`shound` tanpa argumen) membutuhkan console terminal seperti PowerShell, cmd, atau Windows Terminal. Di Git Bash gunakan `winpty shound`.

```bash
shound                                   # menu interaktif
shound recon https://staging.example.com # fingerprint + header + TLS
shound audit https://staging.example.com # audit misconfiguration framework
shound cve --component laravel --version 9.52.4
shound deps ./composer.lock              # audit dependency lokal
shound scan https://staging.example.com -o report.html
```

Untuk CI/CD:

```bash
shound deps . --non-interactive --fail-on high -o report.json
```

Exit code:

| Kode | Arti |
|---|---|
| 0 | OK |
| 1 | Ada temuan ≥ `--fail-on` |
| 2 | Kesalahan argumen, atau `--authorized` tidak diberikan |
| 3 | Target tidak dapat dijangkau |
| 4 | Scan parsial |

## Pengembangan

Kebutuhan: Python 3.10+ dan Git. Docker opsional, untuk test integrasi.

```bash
git clone https://github.com/DhikaRoidHakim/stackhound.git
cd stackhound
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # Linux/macOS: .venv/bin/python

.venv/Scripts/python -m pytest            # unit test (tanpa akses jaringan)
.venv/Scripts/python -m ruff check .
.venv/Scripts/python -m ruff format .
.venv/Scripts/python -m mypy              # strict
.venv/Scripts/shound --help
```

### Test integrasi dengan target Docker

Folder [`tests/targets/`](tests/targets/README.md) berisi target uji yang **sengaja dibuat rentan**, semuanya hanya bisa diakses dari `127.0.0.1`:

- Laravel 12 dan Laravel 10 dengan `.env`, `.git`, log, dan Telescope terbuka,
- server SPA catch-all (soft-404),
- satu situs "bersih" sebagai pembanding.

```bash
docker compose -f tests/targets/docker-compose.yml up -d --build
.venv/Scripts/python -m pytest -m targets
docker compose -f tests/targets/docker-compose.yml down
```

### Struktur proyek

```
shound/
├── cli.py                 # entry point Typer
├── config.py              # konfigurasi: CLI > env > config.json > default
├── core/
│   ├── models.py          # Finding, UnifiedVulnerability, ScanReport
│   ├── session.py         # satu-satunya jalur HTTP ke target
│   ├── redaction.py       # redaksi evidence
│   ├── cve/               # OSV.dev & NVD            (Fase 2)
│   ├── local_audit/       # parser lock file         (Fase 2)
│   └── reporter/          # terminal/JSON/MD/HTML    (Fase 1–3)
├── plugins/               # audit per framework      (Fase 1–3)
└── data/                  # signature, mapping, banner
tests/
├── unit/                  # pytest + respx, jaringan diblokir
├── integration/           # pytest -m targets
└── targets/               # docker compose target uji
```

### Dokumentasi

| File | Isi |
|---|---|
| `docs/StackHound_PRD_v1.1.docx` | Product Requirements Document v1.1.0 |
| [`docs/STATE.md`](docs/STATE.md) | Posisi pengerjaan saat ini |
| [`docs/BACKLOG.md`](docs/BACKLOG.md) | Daftar task per fase |
| [`docs/MEMORY.md`](docs/MEMORY.md) | Log keputusan desain & fakta teknis |
| [`CLAUDE.md`](CLAUDE.md) | Aturan kerja & invariant untuk kontributor (termasuk AI assistant) |

## Roadmap

- [x] **Fase 0 — Fondasi:** package, model data, konfigurasi, HTTP session aman, redaksi, target uji Docker.
- [ ] **Fase 1 — MVP:** CLI & menu interaktif, baseline soft-404, fingerprinting, security header & TLS, plugin Laravel (LRV-01 – LRV-06), laporan terminal + JSON, Security Grade.
- [ ] **Fase 2 — CVE & dependency:** OSV.dev, NVD, cache SQLite, scanner lock file lokal.
- [ ] **Fase 3 — Multi-framework & laporan:** plugin Django, FastAPI, Express, CodeIgniter 4, Generic; laporan Markdown & HTML.

Detail per task ada di [`docs/BACKLOG.md`](docs/BACKLOG.md).

## Lisensi

Belum ditentukan.
