# STATE — Posisi Pengerjaan StackHound

> Diperbarui di akhir setiap sesi kerja. Isinya adalah status saat ini saja; riwayat keputusan ada di `MEMORY.md`.

**Terakhir diperbarui:** 2026-10-27
**Fase aktif:** Fase 0 — Fondasi **selesai** (T-000 s/d T-006). Berikutnya Fase 1.
**Versi PRD acuan:** 1.1.0 (`docs/StackHound_PRD_v1.1.docx`)
**Versi package:** 0.1.0
**Remote git:** `origin` → https://github.com/DhikaRoidHakim/stackhound.git (belum pernah di-push)

## Sudah selesai

- **T-000 – T-005** (sudah di-commit): repo, package, models, config, `TargetSession`, redaksi.
- **T-006** target Docker di `tests/targets/`:
  - `laravel12-debug` (port 8081) dan `laravel10-ignition` (port 8082).
  - `spa-catchall` (port 8083) dan `clean` (port 8084).
  - Smoke test di `tests/integration/test_targets.py`, dijalankan dengan `pytest -m targets`.
- **Banner CLI** dari pemilik produk disimpan di `shound/data/banner.txt` untuk T-102 (D-021).
- **Kualitas:**
  - Unit: 93 lulus, 1 skip (khusus POSIX).
  - Integrasi: 30 lulus terhadap target Docker.
  - `ruff` dan `mypy --strict` bersih.

## Belum di-commit

Tidak ada. Semua pekerjaan Fase 0 sudah di-commit di `main` (commit terakhir `59a8f58`), tapi belum di-push ke `origin`.

## Temuan dari target nyata yang membuat PRD perlu dikoreksi

Detail lengkap ada di MEMORY F-013 s/d F-015.

1. **PRD §3.2.1 (FP-01):** cookie `laravel_session` tidak tetap. Laravel ≥ 11 memakai `<app>-session`, dan namanya mengikuti `APP_NAME`. Sinyal yang lebih andal adalah nilai cookie yang diawali `eyJpdiI6`.
2. **PRD LRV-04:** signature `/vendor/telescope/app.js` tidak ada di Telescope 5. Yang benar adalah `<title>Telescope` dan `window.Telescope =`.
3. **PRD LRV-02:** marker baru mencakup Ignition/Whoops. Laravel ≥ 11 memakai renderer bawaan dengan marker dan format kebocoran versi yang berbeda.

Saat implementasi T-105 dan T-109, ikuti temuan ini (sudah terbukti di target), bukan teks PRD. PRD .docx belum diubah.

## Langkah berikutnya

1. Fase 1 dimulai dari `T-101` (CLI Typer & opsi global), lalu `T-102` (menu interaktif + banner).
2. Container target masih berjalan. Matikan dengan `docker compose -f tests/targets/docker-compose.yml down` jika tidak dipakai.

## Sedang dikerjakan

Tidak ada.

## Blocker

Tidak ada.

## Pertanyaan terbuka (perlu jawaban pemilik produk)

1. Lisensi proyek: MIT, Apache-2.0, atau internal saja? `pyproject.toml` saat ini belum mencantumkan lisensi.
2. Apakah akan dipublikasikan ke PyPI? Ketersediaan nama `stackhound` perlu dicek.
3. Laporan HTML: wajib ada di MVP, atau cukup di Fase 3 sesuai roadmap?
4. Apakah output laporan perlu tersedia dalam bahasa Inggris?
5. Apakah PRD .docx perlu direvisi ke v1.1.1 untuk memuat tiga koreksi di atas?
