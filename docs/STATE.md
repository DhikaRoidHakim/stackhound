# STATE — Posisi Pengerjaan StackHound

> Diperbarui di akhir setiap sesi kerja. Isinya adalah status saat ini saja; riwayat keputusan ada di `MEMORY.md`.

**Terakhir diperbarui:** 2026-10-27
**Fase aktif:** Fase 0 — Fondasi (belum dimulai)
**Versi PRD acuan:** 1.1.0 (`docs/StackHound_PRD_v1.1.docx`)

## Sudah selesai

- PRD v1.0.0 + Addendum dianalisis dan direvisi menjadi PRD v1.1.0 (Word).
- Dokumen kerja dibuat: `CLAUDE.md`, `docs/MEMORY.md`, `docs/STATE.md`, `docs/BACKLOG.md`.

## Isi repo saat ini

```
stackhound/
├── CLAUDE.md
└── docs/
    ├── StackHound_PRD_v1.1.docx
    ├── MEMORY.md
    ├── STATE.md
    └── BACKLOG.md
```

Belum ada kode, belum ada `pyproject.toml`, dan folder ini belum menjadi repo git.

## Langkah berikutnya

1. `T-000` — `git init`, `.gitignore` (Python, `.venv/`, laporan hasil scan), commit awal dokumen.
2. `T-001` — Kerangka package: `pyproject.toml` (entry point `shound`), struktur `shound/`, `tests/`, konfigurasi ruff/mypy/pytest.
3. `T-002` — `core/models.py` sesuai PRD §4.
4. `T-003` s/d `T-006` — config, session (rate limiter), redaction, target Docker uji.

## Sedang dikerjakan

Tidak ada.

## Blocker

Tidak ada.

## Pertanyaan terbuka (perlu jawaban pemilik produk)

1. Lisensi proyek: MIT, Apache-2.0, atau internal saja?
2. Apakah akan dipublikasikan ke PyPI? Ketersediaan nama `stackhound` perlu dicek.
3. Laporan HTML: wajib ada di MVP, atau cukup di Fase 3 sesuai roadmap?
4. Apakah output laporan perlu tersedia dalam bahasa Inggris?
