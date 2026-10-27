# STATE — Posisi Pengerjaan StackHound

> Diperbarui di akhir setiap sesi kerja. Isinya adalah status saat ini saja; riwayat keputusan ada di `MEMORY.md`.

**Terakhir diperbarui:** 2026-10-27
**Fase aktif:** Fase 0 — Fondasi (T-000 s/d T-005 selesai; tinggal T-006)
**Versi PRD acuan:** 1.1.0 (`docs/StackHound_PRD_v1.1.docx`)
**Versi package:** 0.1.0

## Sudah selesai

- PRD v1.1.0 (Word) dan dokumen kerja (`CLAUDE.md`, `docs/*.md`).
- **T-000 – T-002** (sudah di-commit): repo git, `pyproject.toml`, kerangka package, `core/models.py`.
- **T-003** `shound/config.py`:
  - `Settings` dengan `SecretStr` untuk API key.
  - Prioritas nilai CLI > env > file > default.
  - `set_config_value` / `unset_config_value` dan `display_values()` yang memask API key.
  - Penulisan file atomik dengan mode 0600 di POSIX.
- **T-004** `shound/core/session.py`:
  - `TargetSession` dengan whitelist method (GET/HEAD/OPTIONS).
  - `probe_patch()` yang dijaga OPTIONS, rate limiter global, dan semaphore 5.
  - Batas body 1 MiB.
  - Header `User-Agent` + `X-Security-Audit: StackHound/<__version__>` yang tidak bisa ditimpa pemanggil.
  - Retry 429/503 dengan `Retry-After` dan penurunan rate.
  - Redirect hanya ke host yang sama.
  - `HttpResponse` dan `TargetRequestError`.
- **T-005** `shound/core/redaction.py`: `redact()` dan `redacted_evidence()`.
- **Kualitas:**
  - 93 test lulus; 1 di-skip (cek mode file POSIX, karena berjalan di Windows).
  - Coverage total 96%: config, models, dan redaction 100%; session 93%.
  - `ruff check`, `ruff format`, dan `mypy --strict` bersih.

## Belum di-commit

T-003 sampai T-005 beserta pembaruan docs masih berupa perubahan lokal yang belum di-commit.

## Langkah berikutnya

1. `T-006`: target Docker uji di `tests/targets/`:
   - Laravel `APP_DEBUG=true` dengan `.env`, `.git`, log, dan `composer.lock` terekspos, plus Telescope tanpa gate.
   - SPA catch-all.
   - Target bersih.

   Docker 29.9.2 sudah terpasang di mesin dev.
2. Lalu Fase 1, mulai dari `T-101` (CLI Typer & opsi global).

## Sedang dikerjakan

Tidak ada.

## Blocker

Tidak ada.

## Pertanyaan terbuka (perlu jawaban pemilik produk)

1. Lisensi proyek: MIT, Apache-2.0, atau internal saja? `pyproject.toml` saat ini belum mencantumkan lisensi.
2. Apakah akan dipublikasikan ke PyPI? Ketersediaan nama `stackhound` perlu dicek.
3. Laporan HTML: wajib ada di MVP, atau cukup di Fase 3 sesuai roadmap?
4. Apakah output laporan perlu tersedia dalam bahasa Inggris?
