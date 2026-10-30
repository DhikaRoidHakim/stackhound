# STATE — Posisi Pengerjaan StackHound

> Diperbarui di akhir setiap sesi kerja. Isinya adalah status saat ini saja; riwayat keputusan ada di `MEMORY.md`.

**Terakhir diperbarui:** 2026-10-30
**Fase aktif:** Fase 1 — MVP (T-101 s/d T-111 selesai; tinggal T-112). Fase 0 selesai.
**Versi PRD acuan:** 1.1.0 (`docs/StackHound_PRD_v1.1.docx`)
**Versi package:** 0.1.0
**Remote git:** `origin` → https://github.com/DhikaRoidHakim/stackhound.git (tracking `origin/main`)

## Sudah selesai

- **Fase 0 (T-000 – T-006):** repo, package, models, config, `TargetSession`, redaksi, target Docker uji.
- **T-101** CLI Typer:
  - Subcommand `recon`, `audit`, `cve`, `deps`, `scan`, `config show|set|unset`, dan `cache stats|clear`.
  - Opsi global PRD §2.2 dipasang per subcommand.
  - Validasi input ada di `shound/options.py`; gerbang izin di `shound/authorization.py`.
  - Exit code: 2 untuk usage error atau tanpa `--authorized`; 3 jika lock file tidak ditemukan.
  - Mode yang belum diimplementasi lewat `shound/runner.py`: mencetak ringkasan request lalu keluar dengan exit code 2.
  - `shound config` sudah berfungsi penuh.
- **T-102** menu interaktif (`shound/menu.py`, `shound/prompts.py`, `shound/ui.py`):
  - Banner dari `data/banner.txt` dengan versi berjalan.
  - Menu 0–7 dalam bahasa Indonesia, konfirmasi izin sekali per target, dan submenu Pengaturan.
  - Diverifikasi secara visual di console Windows sungguhan.
- **T-103** pre-flight (`shound/core/preflight.py`):
  - DNS (dilewati jika memakai proxy), GET halaman target, dan info TLS dari koneksi (`TlsInfo` di `HttpResponse`).
  - Gagal → exit code 3. Sertifikat self-signed menyarankan `--insecure`.
  - Diuji terhadap server HTTPS lokal dengan sertifikat self-signed (`tests/integration/test_preflight_tls.py`).
- **T-104** baseline soft-404 (`shound/core/baseline.py`):
  - `Baseline.capture()`, `confirm()`, `url_for()`, dan temuan INFO `FP-06`.
  - Di target SPA, signature lemah cocok di `/.env`, `/.git/HEAD`, dan `/telescope`, tapi semuanya tetap ditolak. Di target Laravel, eksposur asli terkonfirmasi.
- **T-105** fingerprint engine (`shound/core/fingerprint.py`, `shound/data/signatures.json`):
  - 15 teknologi dan 37 sinyal (FP-01 s/d FP-05); pasif, tanpa request tambahan.
  - Versi beserta sumbernya dan token distro untuk risiko backport.
  - Hasil di target Docker: Laravel 100% (L10 dan L12), PHP 8.3.36, Apache 2.4.69 (Debian). Di SPA tidak ada framework ≥ 40%; di clean hanya nginx tanpa versi.
  - Versi Laravel terbaca dari halaman debug hasil probe PATCH.
- **T-106** audit header, cookie, CORS, dan disclosure (`shound/core/headers_tls.py`, `shound/data/cookies.json`):
  - SH-01, SH-02, SH-03, dan SH-05 dengan ID turunan (D-027).
  - Hasil di target Docker:
    - Laravel: 7 temuan (CSP, XFO, XCTO, RP, PP, versi Server dan PHP); cookie Laravel lolos.
    - SPA: SH-03.REFLECT HIGH dan SH-03.NULL MEDIUM.
    - Clean: 0 temuan header/cookie/CORS.
- **T-107** audit TLS / SH-04 (`audit_tls` di `shound/core/headers_tls.py`, `TargetSession.tls_handshake`):
  - Mencakup sertifikat tidak valid, sertifikat segera kedaluwarsa, penerimaan TLS 1.0/1.1, dan HTTP yang tidak diarahkan ke HTTPS.
  - Diuji dengan dua server HTTPS lokal sungguhan (modern dan legacy) di `tests/integration/test_tls_local.py`.
  - Semua target Docker berjalan di HTTP, jadi masing-masing mendapat SH-04.HTTP (LOW). Target clean sekarang memiliki tepat 1 temuan, yaitu itu.
- **T-108** kontrak plugin dan loader (`shound/plugins/base.py`, `shound/plugins/__init__.py`).
- **T-109** plugin Laravel LRV-01 s/d LRV-06 (`shound/plugins/laravel.py`, `shound/data/laravel.json`):
  - Di kedua target Laravel, keenam temuan terdeteksi; tidak ada secret palsu maupun email git yang lolos ke temuan.
  - Dipaksa dengan `--framework laravel` di SPA dan clean: nol temuan.
- **Alur per mode** (`runner.execute()`):
  - Semua mode dengan target URL menjalankan pre-flight, baseline, dan fingerprint.
  - `recon`: audit header/cookie/CORS/TLS.
  - `audit`: plugin.
  - `scan`: keduanya.
- **T-110** grading dan exit code (`shound/core/grading.py`, D-031):
  - Security Grade A+ s/d F, ditampilkan dalam panel ringkasan.
  - `--fail-on` → exit code 1; scan parsial → exit code 4.
  - Hasil di target Docker:
    - `audit` Laravel: F (0).
    - `recon` Laravel: D (69).
    - `recon` SPA: F (44).
    - `recon` clean: A+ (97).
  - `recon` dan `audit` kini selesai penuh. `scan`, `cve`, dan `deps` masih exit code 2 sampai engine CVE ada.
- **T-111** reporter terminal + JSON (`shound/core/reporter/`, D-032):
  - `-o laporan.json` menulis `ScanReport` lengkap.
  - Diuji terhadap kedua target Laravel: tidak ada satu pun secret palsu, email git, atau nilai cookie di file JSON.
  - `.md` dan `.html` ditolak sebelum scan dimulai (T-306/T-307).
- **Kualitas:**
  - Unit + integrasi lokal: 405 lulus, 1 skip (khusus POSIX), coverage 94%.
  - Integrasi Docker: 63 lulus (`pytest -m targets`).
  - `ruff` dan `mypy --strict` bersih.

## Status git

Semua pekerjaan sudah di-commit. Cek `git status -sb` untuk melihat apakah `main` sudah di-push (bagian ini sengaja tidak mencatat hash commit agar tidak basi).

## Temuan dari target nyata yang membuat PRD perlu dikoreksi

Detail lengkap ada di MEMORY F-013 s/d F-015.

1. **PRD §3.2.1 (FP-01):** cookie `laravel_session` tidak tetap. Laravel ≥ 11 memakai `<app>-session`, dan namanya mengikuti `APP_NAME`. Sinyal yang lebih andal adalah nilai cookie yang diawali `eyJpdiI6`.
2. **PRD LRV-04:** signature `/vendor/telescope/app.js` tidak ada di Telescope 5. Yang benar adalah `<title>Telescope` dan `window.Telescope =`.
3. **PRD LRV-02:** marker baru mencakup Ignition/Whoops. Laravel ≥ 11 memakai renderer bawaan dengan marker dan format kebocoran versi yang berbeda.

Saat implementasi T-105 dan T-109, ikuti temuan ini (sudah terbukti di target), bukan teks PRD. PRD .docx belum diubah.

## Langkah berikutnya

1. `T-112`: uji penerimaan MVP (PRD §8.1). Kriteria 1–6 bisa diuji di target Docker dan sebagian besar sudah tercakup test integrasi. Kriteria 7 (Windows **dan** Ubuntu, Python 3.10 dan 3.13) butuh lingkungan Linux dan Python 3.10/3.13, yang belum tersedia di mesin ini.
2. Setelah MVP: Fase 2 (CVE & dependency), dimulai dari T-201 (cache SQLite).

## Sedang dikerjakan

Tidak ada.

## Blocker

Tidak ada.

## Catatan lingkungan

Docker Desktop tidak otomatis menyala setelah mesin restart. Jalankan dulu (`%LOCALAPPDATA%\Programs\DockerDesktop\Docker Desktop.exe`), lalu `docker compose -f tests/targets/docker-compose.yml up -d`. Tanpa itu, test `-m targets` di-skip dan `shound` ke target lokal berakhir dengan exit code 3.


Menu interaktif tidak bisa dijalankan di Git Bash/mintty biasa (gunakan `winpty shound`) dan juga tidak dari tool Bash milik Claude. Untuk cek manual, gunakan PowerShell atau Windows Terminal.

## Pertanyaan terbuka (perlu jawaban pemilik produk)

1. Lisensi proyek: MIT, Apache-2.0, atau internal saja? `pyproject.toml` saat ini belum mencantumkan lisensi.
2. Apakah akan dipublikasikan ke PyPI? Ketersediaan nama `stackhound` perlu dicek.
3. Laporan HTML: wajib ada di MVP, atau cukup di Fase 3 sesuai roadmap?
4. Apakah output laporan perlu tersedia dalam bahasa Inggris?
5. Apakah PRD .docx perlu direvisi ke v1.1.1 untuk memuat tiga koreksi di atas?
