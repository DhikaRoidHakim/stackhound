# StackHound (`shound`)

Framework-Based Security Configuration & CVE Auditor.

StackHound adalah CLI Python untuk mengaudit aplikasi web secara **non-intrusive**:

- **Black-box:** fingerprint tech stack, cek security header/TLS, cek misconfiguration per framework (Laravel, Django, FastAPI, Express, CodeIgniter), dan korelasi CVE via OSV.dev + NVD.
- **White-box:** audit lock file lokal (`composer.lock`, `package-lock.json`, `requirements.txt`) terhadap OSV.dev.

> **Disclaimer:** gunakan hanya pada server/aplikasi milik sendiri atau yang memiliki izin audit resmi.

## Status

Dalam pengembangan, Fase 0 (fondasi). Lihat [docs/STATE.md](docs/STATE.md) dan [docs/BACKLOG.md](docs/BACKLOG.md).

## Pengembangan

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"   # Linux/macOS: .venv/bin/python
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check .
.venv/Scripts/python -m mypy shound
```

Spesifikasi lengkap ada di `docs/StackHound_PRD_v1.1.docx`.
