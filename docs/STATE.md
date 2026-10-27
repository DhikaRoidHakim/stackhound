# STATE — Posisi Pengerjaan StackHound

> Diperbarui di akhir setiap sesi kerja. Isinya adalah status saat ini saja; riwayat keputusan ada di `MEMORY.md`.

**Terakhir diperbarui:** 2026-10-27
**Fase aktif:** Fase 0 — Fondasi (T-000 s/d T-002 selesai; T-003 s/d T-006 belum)
**Versi PRD acuan:** 1.1.0 (`docs/StackHound_PRD_v1.1.docx`)
**Versi package:** 0.1.0

## Sudah selesai

- PRD v1.1.0 (Word) dan dokumen kerja (`CLAUDE.md`, `docs/*.md`).
- **T-000:** repo git (branch `main`), `.gitignore`, `.gitattributes` (LF), `README.md`.
- **T-001:** `pyproject.toml` (hatchling, entry point `shound`, extras `dev`), kerangka package `shound/` dan `tests/`, konfigurasi ruff/mypy (strict, seluruh package)/pytest. `.venv` (Python 3.11) sudah terpasang.
- **T-002:** `shound/core/models.py` sesuai PRD §4.
- **Test:** 20 test lulus; coverage `models.py` 100%. `ruff check`, `ruff format --check`, dan `mypy` bersih.
- **Guard jaringan:** `tests/conftest.py` memblokir koneksi non-loopback di semua test yang tidak bertanda `live`.

## Isi repo saat ini

```
stackhound/
├── pyproject.toml, README.md, CLAUDE.md, .gitignore, .gitattributes
├── docs/                      PRD .docx, MEMORY.md, STATE.md, BACKLOG.md
├── shound/
│   ├── __init__.py            __version__ = "0.1.0"
│   ├── __main__.py, cli.py    Typer app: --help, --version (subcommand belum ada)
│   ├── core/models.py         model Pydantic (§4)
│   ├── core/{cve,local_audit,reporter}/   package kosong
│   ├── plugins/               package kosong
│   └── data/                  kosong (.gitkeep)
└── tests/
    ├── conftest.py            guard jaringan
    ├── unit/                  test_models.py, test_cli.py, test_network_guard.py
    └── integration/, fixtures/, targets/   kosong (.gitkeep)
```

## Langkah berikutnya

1. `T-003` — `config.py` (prioritas CLI > env > config.json > default, `platformdirs`).
2. `T-004` — `core/session.py` (token bucket global, whitelist method, header identitas, batas body 1 MB).
3. `T-005` — `core/redaction.py`.
4. `T-006` — target Docker uji di `tests/targets/`.

## Sedang dikerjakan

Tidak ada.

## Blocker

Tidak ada.

## Pertanyaan terbuka (perlu jawaban pemilik produk)

1. Lisensi proyek: MIT, Apache-2.0, atau internal saja? `pyproject.toml` saat ini belum mencantumkan lisensi.
2. Apakah akan dipublikasikan ke PyPI? Ketersediaan nama `stackhound` perlu dicek.
3. Laporan HTML: wajib ada di MVP, atau cukup di Fase 3 sesuai roadmap?
4. Apakah output laporan perlu tersedia dalam bahasa Inggris?
5. **Perbedaan PRD vs kode:** PRD menulis `User-Agent: StackHound-SecurityAudit/1.1` dan `X-Security-Audit: StackHound/1.1`. Angka "1.1" itu versi dokumen PRD, bukan versi tool. Usulan D-013: header memakai `__version__` package. Perlu konfirmasi sebelum T-004.
