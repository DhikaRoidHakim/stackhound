# CLAUDE.md — StackHound (`shound`)

CLI Python untuk audit keamanan web berbasis framework secara **non-intrusive**: fingerprint tech stack, cek misconfiguration (Laravel dulu), security header/TLS, dan korelasi CVE via OSV.dev + NVD. Ada juga mode white-box untuk audit lock file lokal.

## Sumber kebenaran

| File | Isi | Kapan dibaca/diubah |
|---|---|---|
| `docs/StackHound_PRD_v1.1.docx` | PRD lengkap v1.1.0 (spesifikasi, ID cek, model data, roadmap) | Rujukan utama spesifikasi. Jangan diubah tanpa diminta. |
| `docs/STATE.md` | Posisi pengerjaan saat ini, langkah berikutnya, blocker | **Baca di awal setiap sesi. Perbarui di akhir sesi.** |
| `docs/BACKLOG.md` | Daftar task ber-ID (`T-xxx`) per fase | Ambil task dari sini, centang saat selesai. |
| `docs/MEMORY.md` | Log keputusan (`D-xxx`) dan fakta teknis yang tidak terlihat dari kode | Tambahkan entri saat membuat keputusan desain baru. |

Membaca isi PRD (.docx) sebagai teks:

```bash
python -c "import zipfile,re;x=zipfile.ZipFile('docs/StackHound_PRD_v1.1.docx').read('word/document.xml').decode();print(re.sub(r'<[^>]+>','',x.replace('</w:p>','\n')))"
```

Jika kode dan PRD berbeda, jangan diam-diam memilih salah satu: catat di `docs/STATE.md` (bagian "Pertanyaan terbuka") dan tanyakan.

## Lingkungan

- Mesin dev: Windows 11, shell PowerShell (Git Bash juga tersedia). Python 3.11 terpasang; target dukungan Python 3.10–3.13.
- Virtualenv di `.venv/`. Semua path di kode memakai `pathlib` / `platformdirs`, tidak ada path hard-coded gaya POSIX.
- Repo git, branch utama `main`. Line ending LF (`.gitattributes`). Remote `origin`: https://github.com/DhikaRoidHakim/stackhound.git. Push hanya jika diminta.
- Docker tersedia; target uji integrasi dijalankan dengan `pytest -m targets` (lihat `tests/targets/README.md`).

## Perintah (berlaku setelah Fase 0 / T-001 selesai)

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check .
.venv/Scripts/python -m ruff format .
.venv/Scripts/python -m mypy
.venv/Scripts/python -m shound --help
```

Target uji Docker (Laravel debug, SPA catch-all) ada di `tests/targets/` → `docker compose -f tests/targets/docker-compose.yml up -d`.

## Arsitektur singkat

```
shound/cli.py, menu.py      → antarmuka (Typer / Questionary+Rich), tipis, tanpa logika audit
shound/core/session.py      → SATU-SATUNYA jalur HTTP ke target (rate limiter global + header identitas)
shound/core/baseline.py     → baseline soft-404; dipakai semua cek path
shound/core/redaction.py    → redaksi evidence; dipakai sebelum membuat Finding
shound/core/fingerprint.py, headers_tls.py
shound/core/cve/{osv,nvd,engine}.py   → query, normalisasi, dedup
shound/core/local_audit/    → parser lock file → OSV batch
shound/core/cache.py        → SQLite (platformdirs user_cache_dir)
shound/core/grading.py      → skor, grade A+–F, exit code
shound/core/reporter/       → terminal, JSON, Markdown, HTML
shound/plugins/             → BasePlugin + plugin per framework
shound/data/                → signatures.json, cpe_mapping.json, ecosystem_mapping.json, template
```

## Aturan wajib (invariant)

Melanggar aturan di bawah dianggap bug, walaupun test lulus.

1. **Non-destruktif.** Request ke target hanya `GET`, `HEAD`, `OPTIONS`. Satu-satunya pengecualian adalah `PATCH /` di LRV-02, dan itu hanya boleh dikirim jika `OPTIONS /` membuktikan PATCH tidak diizinkan, tanpa body, dan bisa dimatikan dengan `--no-method-probe`. Tidak ada payload eksploit, brute-force, fuzzing, atau pengunduhan object `.git`.
2. **Semua HTTP ke target lewat `core/session.py`.** Jangan membuat `httpx.Client` baru di plugin. Session inilah yang menegakkan rate limit (default 5 rps), batas body 1 MB, dan header `X-Security-Audit` yang selalu dikirim.
3. **Evidence wajib diredaksi** lewat `core/redaction.py` sebelum masuk ke `Finding`. Nilai `.env`, kredensial di URL, dan token tidak boleh muncul di laporan, log, maupun cache. Isi log file tidak pernah disimpan. Setiap cek eksposur baru wajib punya test yang memastikan secret fixture tidak bocor.
4. **Cek path wajib lolos baseline.** Status 200 saja tidak cukup: harus cocok signature konten DAN tidak mirip respons baseline soft-404 (`ctx.baseline.confirm()`).
5. **"Kosong" ≠ "aman".** CPE tidak dikenal NVD → status UNKNOWN. Versi tidak diketahui atau unpinned → `unaudited_components`.
6. **NVD:** selalu pakai `isVulnerable`, paginate dengan `startIndex`, jeda 6 s (tanpa key) / 0,6 s (dengan key). Framework (Laravel, Django, dll.) tidak di-query ke NVD; ditangani OSV.
7. **OSV:** skor CVSS dihitung dari vector string; `fixed_version` diambil dari range yang memuat versi terdeteksi. Jangan mengambil sembarang event `fixed`.
8. **Unit test tidak boleh menyentuh jaringan.** Pakai `respx` dan fixture terekam di `tests/fixtures/`. Test API sungguhan diberi marker `@pytest.mark.live`.
9. **ID cek stabil** (`FP-01`, `SH-02`, `LRV-03`, ...). Cek baru mendapat ID baru; ID lama tidak dipakai ulang.

## Konvensi kode

- Python 3.10+: `X | None`, `list[str]`, type hint lengkap, lolos `mypy` dan `ruff`.
- Pydantic v2: field opsional selalu diberi `= None` secara eksplisit; list memakai `Field(default_factory=list)`.
- I/O jaringan memakai async (`httpx.AsyncClient`); CLI memanggilnya dengan `asyncio.run`.
- Nama identifier dan komentar kode dalam **bahasa Inggris**. Teks yang dilihat pengguna (output CLI, laporan, remediation) dalam **bahasa Indonesia**.
- Pola deteksi (cookie, header, path, marker) disimpan di `shound/data/*.json`, tidak di-hard-code di logika.
- Dependency baru harus dicatat alasannya di `docs/MEMORY.md`.

## Konvensi commit

Gunakan gaya Conventional Commits, tanpa label fase ("Phase 0/1"). **Judul dan body commit ditulis dalam bahasa Indonesia**; hanya prefiks tipe yang tetap dalam bahasa Inggris.

- `feat:` fitur baru
- `update:` penyempurnaan atau perubahan pada fitur yang sudah ada
- `fix:` perbaikan bug
- `docs:` dokumentasi
- `test:` test saja
- `refactor:` perubahan struktur tanpa perubahan perilaku
- `chore:` tooling, dependency, atau konfigurasi

Scope opsional. Contoh: `feat(cli): tambah subcommand scan dan opsi global`, `update: perbarui status di STATE.md`. ID task boleh ditaruh di body (misalnya "Refs: T-101").

## Alur kerja per sesi

1. Baca `docs/STATE.md`, lalu ambil task berikutnya dari `docs/BACKLOG.md`.
2. Kerjakan; tulis atau perbarui test bersama kodenya.
3. Jalankan `pytest`, `ruff`, dan `mypy` sebelum menyatakan selesai.
4. Centang task di `BACKLOG.md`, perbarui `STATE.md` (apa yang selesai, apa berikutnya, blocker), dan tambahkan keputusan baru di `MEMORY.md`.
