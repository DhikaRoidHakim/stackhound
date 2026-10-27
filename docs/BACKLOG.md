# BACKLOG — StackHound

Format: `- [ ] T-xxx — judul` diikuti kriteria selesai. Rujukan `§` mengacu ke PRD v1.1.0. Setelah selesai, centang `[x]` dan pindahkan catatan penting ke `STATE.md` / `MEMORY.md`.

## Fase 0 — Fondasi (Hari 1–2)

- [x] **T-000 — Inisialisasi repo**
  `git init`, `.gitignore` (Python, `.venv/`, `*.html`/`*.json` laporan di root), `README.md` singkat, commit awal.
- [x] **T-001 — Kerangka package**
  `pyproject.toml` (hatchling/setuptools, Python ≥ 3.10, entry point `shound = shound.cli:app`, extras `dev`). Struktur folder sesuai PRD §5. Konfigurasi ruff, mypy (strict untuk `shound/core`), dan pytest (`asyncio_mode = auto`, marker `live`).
  Selesai jika `pip install -e ".[dev]"`, `shound --help`, `pytest`, `ruff`, dan `mypy` semuanya berjalan.
- [x] **T-002 — Model data** (`core/models.py`, §4)
  Membuat `Severity`, `Confidence`, `VersionSource`, `Evidence`, `Finding`, `UnifiedVulnerability`, dan `ScanReport`. Unit test untuk serialisasi JSON dan nilai default.
- [x] **T-003 — Konfigurasi** (`config.py`, §3.8.1)
  Prioritas CLI > env > `config.json` > default; lokasi via `platformdirs`; API key termask; file `0600` di POSIX.
- [x] **T-004 — HTTP session** (`core/session.py`, §6.2–6.3)
  `httpx.AsyncClient` dengan token bucket global, konkurensi maksimal 5, batas body 1 MB, header `User-Agent` + `X-Security-Audit`, penanganan `429`/`Retry-After`, proxy, `--insecure`, dan whitelist method (GET/HEAD/OPTIONS, plus PATCH hanya lewat API khusus probe).
  Test: rate terukur ≤ batas; method lain ditolak.
- [x] **T-005 — Redaksi** (`core/redaction.py`, §3.7.4)
  Redaksi nilai env, kredensial URL, AWS key, JWT, Bearer, private key; potong ke 500 karakter. Test berbasis fixture berisi secret.
- [x] **T-006 — Target uji Docker** (`tests/targets/`)
  (a) Laravel `APP_DEBUG=true` + `.env`, `.git`, `storage/logs`, `composer.lock` terekspos, Telescope tanpa gate; (b) SPA catch-all yang selalu 200; (c) target bersih dengan header lengkap.

## Fase 1 — MVP (Minggu 1–2)

- [x] **T-101 — CLI Typer & opsi global** (§2.2)
  Semua subcommand terdaftar (yang belum diimplementasi menampilkan pesan "belum tersedia"). Mode non-interaktif otomatis jika stdin bukan TTY. `--authorized` wajib untuk target URL (exit code 2).
- [x] **T-102 — Menu interaktif** (§2.1)
  Banner, disclaimer, menu 0–7, konfirmasi otorisasi per target.
  **Banner wajib persis seperti `shound/data/banner.txt`** (permintaan pemilik produk). Placeholder `{version}` diisi `__version__` (D-013); jangan di-hard-code `v1.0.0`. Banner juga ditampilkan di awal `shound` tanpa argumen.
- [x] **T-103 — Pre-flight check** (§2.3)
  Validasi URL, DNS, konektivitas, info TLS dasar → exit code 3 jika gagal.
- [x] **T-104 — Baseline soft-404** (`core/baseline.py`, §3.2.2)
  Dua path acak, normalisasi body, `confirm(response, signature)` dengan rasio kemiripan < 0,9.
- [x] **T-105 — Fingerprint engine** (`core/fingerprint.py`, `data/signatures.json`, §3.2)
  FP-01 s/d FP-05, skor confidence berbobot, ekstraksi versi + `version_source`.
- [ ] **T-106 — Security headers & cookie & CORS** (`core/headers_tls.py`, §3.3)
  SH-01 (HSTS/CSP/XFO/XCTO/RP/PP), SH-02 (dengan pengecualian `XSRF-TOKEN`), SH-03, SH-05.
- [ ] **T-107 — TLS audit** (SH-04)
  Validitas sertifikat, kedaluwarsa < 30 hari, TLS 1.0/1.1 diterima, redirect HTTP → HTTPS.
- [ ] **T-108 — Kontrak plugin & registry** (`plugins/base.py`, `plugins/__init__.py`, §3.4.1)
  `BasePlugin`, `ScanContext`, `PluginResult`, loader berdasarkan ambang confidence 0,8 / 0,4.
- [ ] **T-109 — Plugin Laravel LRV-01 s/d LRV-06** (§3.4.2)
  Termasuk guard OPTIONS untuk LRV-02, header `Range` untuk LRV-03, tanpa follow-redirect untuk LRV-04, ekstraksi `laravel_version` dari Ignition.
  Test: nol false positive terhadap target SPA catch-all; tidak ada secret di output.
- [ ] **T-110 — Grading & exit code** (`core/grading.py`, §3.7.2, §3.7.5)
- [ ] **T-111 — Reporter terminal + JSON** (§3.7.1, §3.7.3)
- [ ] **T-112 — Uji penerimaan MVP** (§8.1)
  Jalankan ketujuh kriteria penerimaan terhadap target Docker, di Windows dan Linux.

## Fase 2 — CVE & Dependency (Minggu 3)

- [ ] **T-201 — Cache SQLite** (`core/cache.py`, §3.8.2)
  WAL, TTL, cache negatif, `schema_version`, `--no-cache` / `--refresh`, `shound cache stats|clear`.
- [ ] **T-202 — Versioning per ekosistem** (`core/versioning.py`)
  PyPI (`packaging`), npm (semver), Packagist (normalisasi Composer). Test tabel perbandingan.
- [ ] **T-203 — Klien OSV** (`core/cve/osv.py`, §3.5.3)
  Single query + pagination, batch (chunk 1.000) + pagination per query, dedup ID, hydrate paralel (semaphore 10), skor dari vector CVSS, pemilihan `fixed_version` berbasis interval. Fixture terekam.
- [ ] **T-204 — Klien NVD** (`core/cve/nvd.py`, §3.5.2)
  Validasi CPE, `isVulnerable`, pagination, throttling 6 s / 0,6 s, backoff 10/20/40 s, prioritas CVSS `Primary`, abaikan `Rejected`, label backport distro.
- [ ] **T-205 — CVE engine** (`core/cve/engine.py`, §3.5.1, §3.5.6)
  Routing komponen → OSV/NVD via `ecosystem_mapping.json` / `cpe_mapping.json`; merge berdasarkan irisan alias.
- [ ] **T-206 — Parser lock file lokal** (`core/local_audit/`, §3.6)
  `composer.lock`, `package-lock.json` v1/v2/v3, `requirements.txt` (`==` saja, ikuti `-r`, PEP 503). Komponen unaudited dicatat.
- [ ] **T-207 — Subcommand `deps` & menu [4]**
  Termasuk input berupa folder proyek.
- [ ] **T-208 — Resolusi versi Lapisan 1 & 3** (§3.5.5)
  Prompt interaktif + `--version komponen=x.y.z`; integrasi LRV-05 (`composer.lock` terekspos → OSV batch).
- [ ] **T-209 — Subcommand `cve` & integrasi ke `scan`**

## Fase 3 — Multi-Framework & Laporan (Minggu 4)

- [ ] **T-301 — Plugin Generic Web** (§3.4.3)
- [ ] **T-302 — Plugin FastAPI** (`/docs`, `/redoc`, `/openapi.json`)
- [ ] **T-303 — Plugin Django** (halaman debug, `/admin/`, `/static/` listing)
- [ ] **T-304 — Plugin Express** (`X-Powered-By`, stack trace, `package*.json` terekspos)
- [ ] **T-305 — Plugin CodeIgniter 4** (debug toolbar, `/writable/logs/`, `.env`)
- [ ] **T-306 — Ekspor Markdown**
- [ ] **T-307 — Ekspor HTML** (Jinja2 autoescape, file tunggal, tanpa JS eksternal)
- [ ] **T-308 — Entry point plugin pihak ketiga** (`shound.plugins`)
- [ ] **T-309 — Full scan end-to-end & README penggunaan**

## Icebox / Backlog

- [ ] Output SARIF untuk GitHub Code Scanning.
- [ ] Lapisan 2 deteksi versi: heuristik aset (misal hash `livewire.js` → versi Livewire).
- [ ] Parser `poetry.lock`, `uv.lock`, `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`.
- [ ] Docker image resmi & GitHub Action siap pakai.
- [ ] Dukungan penuh CVSS v4.0 di grading.
- [ ] Antarmuka & laporan bahasa Inggris (`--lang en`).
- [ ] Publikasi ke PyPI (menunggu keputusan lisensi & nama).
