# STATE — Posisi Pengerjaan StackHound

> Diperbarui di akhir setiap sesi kerja. Isinya adalah status saat ini saja; riwayat keputusan ada di `MEMORY.md`.

**Terakhir diperbarui:** 2026-10-27
**Fase aktif:** Fase 1 — MVP (T-101 s/d T-105 selesai). Fase 0 selesai.
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
- `runner.execute()` menjalankan pre-flight, baseline, dan fingerprint untuk mode dengan target URL, lalu mencetak "belum tersedia" untuk pemeriksaan lanjutan.
- **Kualitas:**
  - Unit: 268 lulus, 1 skip (khusus POSIX), coverage 93%.
  - Integrasi: 44 lulus (`pytest -m targets`).
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

1. `T-106`: security header, cookie, CORS, dan information disclosure (SH-01, SH-02, SH-03, SH-05). Respons pre-flight bisa dipakai ulang.
2. `T-107`: audit TLS (SH-04). `TlsInfo` sudah tersedia di `HttpResponse`.
3. Ganti pesan "belum tersedia" di `runner.probe_target()` dengan pipeline recon sungguhan (findings + laporan, T-110/T-111).

## Sedang dikerjakan

Tidak ada.

## Blocker

Tidak ada.

## Catatan lingkungan

Menu interaktif tidak bisa dijalankan di Git Bash/mintty biasa (gunakan `winpty shound`) dan juga tidak dari tool Bash milik Claude. Untuk cek manual, gunakan PowerShell atau Windows Terminal.

## Pertanyaan terbuka (perlu jawaban pemilik produk)

1. Lisensi proyek: MIT, Apache-2.0, atau internal saja? `pyproject.toml` saat ini belum mencantumkan lisensi.
2. Apakah akan dipublikasikan ke PyPI? Ketersediaan nama `stackhound` perlu dicek.
3. Laporan HTML: wajib ada di MVP, atau cukup di Fase 3 sesuai roadmap?
4. Apakah output laporan perlu tersedia dalam bahasa Inggris?
5. Apakah PRD .docx perlu direvisi ke v1.1.1 untuk memuat tiga koreksi di atas?
