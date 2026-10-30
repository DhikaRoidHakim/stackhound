# MEMORY — Keputusan & Fakta Teknis StackHound

Berisi keputusan desain (`D-xxx`) beserta alasannya, dan fakta teknis (`F-xxx`) yang tidak terlihat dari kode. Entri baru ditambahkan di bawah; entri lama tidak dihapus. Jika ada keputusan yang dibatalkan, tandai **[DIGANTI oleh D-yyy]**.

## Keputusan

### D-001 — PRD v1.1.0 jadi acuan tunggal (2026-10-27)
PRD v1.0.0 dan Addendum NVD/OSV digabung menjadi `docs/StackHound_PRD_v1.1.docx`.
**Alasan:** di v1.0.0 kedua dokumen itu saling bertentangan, misalnya path cache dan peran NVD untuk Laravel.

### D-002 — Stack inti (2026-10-27)
Typer + Questionary + Rich, `httpx[http2]` async, BeautifulSoup4 + lxml, Pydantic v2, Jinja2, `platformdirs`, `packaging`, `cvss`. Untuk dev: pytest, pytest-asyncio, respx, ruff, mypy.
**Alasan:** banyak endpoint diperiksa sekaligus sehingga butuh async; `platformdirs` agar jalan di Windows; `cvss` karena OSV hanya memberi vector string.

### D-003 — Framework hanya di-query ke OSV, bukan NVD (2026-10-27)
NVD dipakai untuk infrastruktur saja (php, nginx, apache, openssl, iis).
**Alasan:** menghindari duplikasi CVE, dan nama package OSV lebih presisi daripada CPE framework yang belum tentu benar.

### D-004 — Redaksi evidence wajib & terpusat (2026-10-27)
Semua evidence melewati `core/redaction.py`. Body mentah dari target tidak pernah disimpan, termasuk di cache.
**Alasan:** laporan JSON/HTML sering menjadi artifact CI. Tanpa redaksi, tool ini justru akan membocorkan secret yang ditemukannya.

### D-005 — Baseline soft-404 untuk semua cek path (2026-10-27)
**Alasan:** SPA, catch-all route, dan WAF sering mengembalikan 200 untuk path apa pun, sehingga cek berdasarkan status code saja menghasilkan false positive massal.

### D-006 — Probe PATCH LRV-02 dijaga dengan OPTIONS (2026-10-27)
Probe default aktif, tapi hanya dikirim jika `Allow` dari `OPTIONS /` tidak memuat PATCH. Bisa dimatikan dengan `--no-method-probe`.
**Alasan:** dengan syarat itu router dijamin menolak request (405) sebelum handler berjalan, jadi tetap non-destruktif. Lihat F-004.

### D-007 — Header identitas tidak bisa dimatikan (2026-10-27)
`X-Security-Audit: StackHound/<versi>` selalu dikirim, walaupun User-Agent diganti.
**Alasan:** Blue Team harus selalu bisa mengenali trafik audit.

### D-008 — Otorisasi eksplisit (2026-10-27)
Mode interaktif menanyakan konfirmasi sekali per target per sesi. Mode non-interaktif wajib memakai `--authorized`; tanpa flag itu keluar dengan exit code 2 sebelum ada request apa pun.

### D-009 — Exit code (2026-10-27)
| Kode | Arti |
|---|---|
| 0 | OK |
| 1 | Ada temuan ≥ `--fail-on` |
| 2 | Usage error |
| 3 | Pre-flight gagal |
| 4 | Scan parsial |

Jika kode 1 dan 4 sama-sama berlaku, kode 1 yang dipakai.

### D-010 — Formula Security Grade (2026-10-27)
- Skor awal 100, dikurangi penalti: CRITICAL 40 / HIGH 20 / MEDIUM 8 / LOW 3 / INFO 0.
- Penalti dikalikan faktor confidence: HIGH 1,0 / MEDIUM 0,75 / LOW 0,25.
- Vulnerability dikelompokkan per komponen: penalti severity tertinggi + 1 per kerentanan tambahan (maksimal +10). Dependency dev × 0,5.
- Grade: A+ ≥ 97 (tanpa temuan MEDIUM ke atas), A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.
- Ada CRITICAL ber-confidence HIGH → otomatis F. Ada HIGH ber-confidence HIGH → maksimal C.

### D-011 — Bahasa (2026-10-27)
Kode dan komentar dalam bahasa Inggris. Output CLI dan laporan dalam bahasa Indonesia. Antarmuka bahasa Inggris masuk backlog.

### D-012 — Lokasi file pengguna (2026-10-27)
- Config: `platformdirs.user_config_dir("shound")/config.json`
- Cache: `platformdirs.user_cache_dir("shound")/cache.db` (SQLite WAL)

Keduanya menggantikan `~/.shound/` dari v1.0.0.

### D-013 — Versi package & header identitas (2026-10-27) — *disetujui pemilik produk 2026-10-27*
Versi package dimulai dari `0.1.0` (di `shound/__init__.py`, dibaca hatchling) dan menjadi `1.0.0` saat MVP dirilis. `User-Agent` dan `X-Security-Audit` memakai `__version__`, bukan angka "1.1" seperti contoh di PRD.
**Alasan:** "1.1" di PRD adalah versi dokumen. Header harus menunjukkan versi tool yang benar-benar berjalan.

### D-014 — Model Pydantic menolak field asing (2026-10-27)
Semua model di `core/models.py` mewarisi `_StrictModel` (`extra="forbid"`). Selain itu, `cvss_score` dibatasi 0–10, `score` dibatasi 0–100, dan `fingerprint` bertipe `dict[str, Any]` (agar lolos mypy strict). Ini tambahan dari PRD §4, bukan perubahan makna.
**Alasan:** typo nama field saat membangun model secara internal langsung gagal, tidak diam-diam hilang.

### D-015 — Tooling (2026-10-27)
- Build backend hatchling, dengan versi dinamis dari `shound/__init__.py`.
- mypy strict untuk seluruh `shound/`, memakai plugin `pydantic.mypy`.
- ruff dengan rule set `E,F,W,I,B,UP,SIM,RUF,ASYNC,PT`; RUF001–003 dimatikan karena teks berbahasa Indonesia; panjang baris 100.
- pytest dengan `asyncio_mode=auto`; test `live` di-skip secara default (`-m 'not live'`).
- `pytest-cov` ditambahkan ke dependency dev untuk mengukur target coverage 80% (PRD §7).

### D-016 — Guard jaringan di test (2026-10-27)
`tests/conftest.py` mem-patch `socket.socket.connect` sehingga koneksi selain loopback raise `RuntimeError`. Loopback tetap diizinkan karena asyncio di Windows memakai koneksi lokal untuk self-pipe.
**Alasan:** menegakkan aturan "unit test tidak boleh menyentuh jaringan" secara otomatis, tanpa dependency tambahan.

### D-017 — Konfigurasi (T-003, 2026-10-27)
- `nvd_api_key` bertipe `SecretStr`, sehingga tidak muncul di `repr` maupun `model_dump_json`. Nilai aslinya hanya diambil lewat `.get_secret_value()`.
- `config.json` hanya menyimpan nilai yang di-set eksplisit oleh pengguna. Nilai disimpan setelah koersi tipe (misalnya `"25"` → `25.0`).
- Penulisan file atomik (tmp lalu `os.replace`), dibuat dengan mode `0600` di POSIX.
- Nilai env yang kosong diabaikan. Key yang tidak dikenal di file → `ConfigError`.
- Batas: `timeout` 0–300 detik, `rate_limit` 0–20.

### D-018 — Desain HTTP session (T-004, 2026-10-27)
Detail berikut tidak ditentukan PRD dan ditetapkan di sini:
- **Rate limiter:** token bucket berkapasitas 1, yaitu jarak antar-request `1/rate`. Dengan kapasitas lebih besar, burst + refill bisa melebihi `rate` dalam satu jendela 1 detik.
- **Throttling:** saat target membalas 429/503, rate dibagi dua (minimal 0,5 rps) dan semua request dijeda global sesuai `Retry-After`. Jika header itu absen, jeda 5 detik; maksimal 60 detik. Retry paling banyak 2 kali, lalu respons terakhir dikembalikan apa adanya.
- **Redirect:** tidak diikuti secara default. Jika diminta (`follow_redirects=True`), redirect diikuti oleh session sendiri, bukan oleh httpx, agar setiap hop terkena rate limit. Hanya host yang sama yang diikuti (`www.` diabaikan), maksimal 5 hop. Redirect ke host lain tidak diikuti karena di luar target yang diizinkan.
- **`trust_env=False`:** variabel `HTTP(S)_PROXY` dan netrc dari sistem diabaikan. Proxy hanya diambil dari config shound (`SHOUND_PROXY` / `--proxy`), supaya hasil scan reproducible dan kredensial netrc tidak terkirim ke target.
- **PATCH:** request PATCH hanya bisa dikirim lewat `probe_patch()`, dengan body kosong (`Content-Length: 0`). `request()` menolak method selain GET/HEAD/OPTIONS sebelum ada I/O.
- **Error transport** dibungkus menjadi `TargetRequestError`, sehingga plugin tidak bergantung langsung pada httpx.

### D-019 — Redaksi (T-005, 2026-10-27)
- Pola redaksi ditulis di kode (`core/redaction.py`), bukan di `data/*.json`. Ini kontrol keamanan, dan tidak boleh bisa dilemahkan dengan mengedit file data.
- Urutannya: redaksi dulu, baru dipotong ke 500 karakter, supaya pemotongan tidak menyisakan potongan secret yang lolos dari pola.
- Semua nilai baris `.env` dengan key huruf besar dimask, termasuk yang tidak tampak rahasia seperti `DB_HOST`.
- Key yang sensitif (password, secret, token, api_key, auth, dan sejenisnya) dimask dalam format JSON, YAML, query string, maupun ini.
- Yang juga dimask: kredensial di URL (sampai `@` terakhir di authority), Bearer/Basic, JWT, AWS key id, token GitHub/Slack/Stripe/Google, `base64:` APP_KEY, dan blok private key (termasuk yang terpotong).
- Plugin membuat `Evidence` lewat `redacted_evidence()`, yang meredaksi url, snippet, dan note sekaligus.
- Over-redaction (misalnya key `author`) diterima; under-redaction tidak.

### D-020 — Target uji Docker (T-006, 2026-10-27)
- Empat service di `tests/targets/docker-compose.yml`, semuanya di-bind ke `127.0.0.1` saja.
- Laravel dibuat dalam dua versi (12 dan 10) karena halaman debug-nya berbeda (lihat F-015).
- Miskonfigurasi yang dimodelkan: web root = root proyek, ditambah `.htaccess` ala shared hosting.
- Secret palsu ditanam di `configure.sh`.
- Test bertanda `targets` dikecualikan dari `pytest` biasa (`addopts`) dan otomatis di-skip kalau container belum jalan.

### D-022 — Arsitektur CLI & menu (T-101/T-102, 2026-10-27)
- **Alur bersama:** `options.py` memvalidasi input menjadi `ScanRequest`; `authorization.py` (gerbang izin); `runner.execute()` menjalankan request. `cli.py` dan `menu.py` hanya mengumpulkan input, sehingga hasil dari menu dan dari CLI identik.
- **Opsi "global" dipasang per subcommand**, bukan di root, supaya bisa ditulis setelah subcommand. Root hanya punya `--version` (versi tool). `--version` di subcommand bermakna komponen: `KOMPONEN=VERSI`, atau versi saja jika memakai `cve --component`.
- **Mode yang belum diimplementasi** mencetak ringkasan request lalu keluar dengan **exit code 2**, supaya job CI yang sudah memanggil `shound` tidak lulus secara keliru.
- **URL target:** wajib http/https; kredensial di URL (`user:pass@`) ditolak; fragment dibuang; host dijadikan huruf kecil.
- **Kunci otorisasi:** `scheme://host:port`. Port berbeda dianggap target berbeda.
- **`deps`:** menerima file atau folder proyek. File tidak ditemukan → exit code 3.
- **`--no-cache` + `--refresh`** dipakai bersamaan → exit code 2.
- **Menu memakai protocol `Prompts`** (`QuestionaryPrompts` untuk produksi, `ScriptedPrompts` di test). Jawaban `None` berarti batal: kembali ke menu, atau keluar jika terjadi di menu utama.

### D-024 — Pre-flight (T-103, 2026-10-27)
- **Urutan:** DNS (`getaddrinfo`), lalu GET halaman target dengan redirect host-sama, lalu catatan TLS.
- **Halaman hasil pre-flight disimpan** di `PreflightResult.response` agar fingerprinting tidak mengulang request.
- **Kapan exit code 3:** DNS gagal atau kosong, koneksi gagal, atau sertifikat tidak bisa diverifikasi. Untuk kasus sertifikat, pesannya menyarankan `--insecure`. Status HTTP apa pun (termasuk 5xx) dianggap target bisa dijangkau.
- **Peringatan (bukan kegagalan):** redirect ke host lain, halaman 5xx, `--insecure` aktif, dan sertifikat kedaluwarsa atau kurang dari 30 hari lagi.
- **Dengan proxy, DNS lokal dilewati**, karena host internal mungkin hanya bisa di-resolve oleh proxy.
- **Info TLS (`TlsInfo`) melekat di setiap `HttpResponse`.** Sumbernya `network_stream` httpcore, jadi tidak perlu koneksi TLS terpisah yang melewati session dan proxy. Detail sertifikat hanya tersedia jika sertifikatnya terverifikasi (lihat F-021). Analisis TLS lengkap (versi lama, dsb.) tetap tugas SH-04 / T-107.

### D-025 — Baseline soft-404 (T-104, 2026-10-27)
- **Probe:** `shound-<16 hex acak>` dan `shound-<16 hex acak>.txt`, nilainya baru di setiap scan.
- **Base path:** probe dan semua cek path di-resolve relatif ke direktori target (`base_url()`): `/app` dan `/app/index.php` sama-sama menjadi `/app/`. Plugin wajib memakai `baseline.url_for(path)`.
- **Normalisasi body sebelum dibandingkan:**
  - Path yang di-echo (minimal 3 karakter) diganti, karena halaman 404 sering menampilkan path yang diminta.
  - Hex 8 karakter atau lebih, token 20 karakter atau lebih, angka, dan whitespace juga diganti.
- **Mirip baseline** jika hash sama, atau rasio `difflib` ≥ 0,9. Perbandingan hanya pada 20.000 karakter pertama supaya biayanya terbatas.
- **`confirm()`:** status harus 200 atau 206 (respons `Range` LRV-03), signature (regex atau callable) harus cocok, dan body tidak mirip baseline.
- **Jika semua probe gagal**, `confirm()` hanya bergantung pada signature. Kondisi ini ditampilkan sebagai "baseline tidak tersedia".
- **ID baru `FP-06`** (INFO "Target memakai soft-404"). PRD hanya menyebut temuan INFO tanpa ID.

### D-026 — Fingerprint engine (T-105, 2026-10-27)
- **Pasif.** `fingerprint(observations)` hanya memeriksa respons yang sudah diambil: halaman pre-flight, probe baseline (ditandai `not_found=True`), dan nanti probe plugin, misalnya respons PATCH LRV-02 untuk versi Laravel. Fingerprint tidak mengirim request sendiri.
- **Pemetaan ID cek:**
  - cookie = FP-01
  - header = FP-02
  - body = FP-03
  - body dengan `on: not_found` = FP-04
  - pattern dengan grup `(?P<version>)` + `version_source` = FP-05
- **Confidence** adalah jumlah bobot sinyal yang berbeda (satu sinyal dihitung sekali walau cocok di banyak respons), dibatasi maksimal 1,0. Ambangnya: STRONG ≥ 0,8, LIKELY ≥ 0,4.
- **`implies`** hanya satu tingkat dan hanya dari deteksi ≥ LIKELY (misalnya laravel → php). Teknologi yang di-imply mendapat confidence yang sama dengan sumbernya.
- **Token distro hanya dibaca dari nilai header milik komponen itu sendiri.** Contohnya `(Debian)` di `Server` berlaku untuk Apache, tidak untuk PHP. Image PHP resmi dikompilasi dari source.
- **Bukti cookie tidak pernah memuat nilai cookie**, hanya bagian yang cocok dengan pola (prefiks konstan `eyJpdiI6`). Semua bukti melewati `redact()`.
- **Perbedaan dari bobot PRD §3.2.1:**
  - Cookie Laravel memakai pola `*_session` / `*-session` + nilai `eyJpdiI6` (F-013), bukan nama literal.
  - Sinyal baru:
    - `laravel.cookie.encrypted` (0,3)
    - halaman 404 Laravel (0,5)
    - debug renderer Laravel ≥ 11 (1,0)
    - 404 default Django (0,4)
    - `PHPSESSID` (0,5)
    - ASP.NET, Next.js, dan WordPress
  - FastAPI tidak lagi dideteksi lewat `/openapi.json` dan `/docs`, karena keduanya butuh request tambahan; itu tugas plugin FastAPI (T-302). Penggantinya: 404 JSON `{"detail":"Not Found"}` (0,5) dan `Server: uvicorn` (0,3).
- **`VersionSource.HTML_META`** ditambahkan untuk `<meta name="generator">`.

### D-027 — Audit header, cookie, CORS, dan disclosure (T-106, 2026-10-27)
- **ID turunan per pemeriksaan** (PRD hanya menulis SH-01/02/03/05):
  - `SH-01.HSTS`, `.CSP`, `.XFO`, `.XCTO`, `.RP`, `.PP`
  - `SH-02.HTTPONLY`, `.SECURE`, `.SAMESITE`
  - `SH-03.REFLECT`, `.WILDCARD`, `.NULL`
  - `SH-05.SERVER`, `.POWERED-BY`, `.FRAMEWORK`
- **SH-01:**
  - HSTS hanya dinilai pada respons HTTPS.
  - CSP mode report-only dianggap tidak ada.
  - Jika ada beberapa header CSP, CSP dianggap lemah hanya bila **semua** policy lemah (semua policy ditegakkan browser).
  - Lemah berarti: tidak ada script-src/default-src, ada wildcard (`*`, `http:`, `https:`), atau `'unsafe-inline'` tanpa nonce/hash.
  - XFO `ALLOW-FROM` dianggap tidak ada. CSP `frame-ancestors` menggantikan XFO.
  - Referrer-Policy dinilai dari token terakhir.
  - `Feature-Policy` lama diterima sebagai Permissions-Policy.
- **SH-02:**
  - Hanya cookie sensitif yang dinilai. Klasifikasinya ada di `data/cookies.json`: pola nama session dan daftar nama cookie CSRF.
  - HttpOnly hanya diwajibkan untuk cookie session, bukan cookie CSRF.
  - Secure hanya dinilai di HTTPS. Cookie yang sedang dihapus (expired / Max-Age=0) diabaikan.
  - Satu finding per pemeriksaan, dengan satu evidence per cookie. Nilai cookie tidak pernah ditampilkan.
- **SH-03:**
  - Dua GET tambahan, dengan `Origin: https://shound-origin-check.invalid` dan `Origin: null`.
  - `Access-Control-Allow-Origin: *` tanpa kredensial **tidak** dilaporkan, karena wajar untuk API publik.
  - Origin dipantulkan + kredensial = HIGH; tanpa kredensial = MEDIUM.
- **SH-05:** versi (pola `\d+\.\d+`) di `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, atau `X-Generator` → LOW. Header tanpa versi (misalnya `X-Powered-By: Express`) tidak dilaporkan.
- **Target SPA** sekarang juga sengaja salah konfigurasi CORS (memantulkan Origin + kredensial) untuk menguji SH-03. Target clean wajib menghasilkan nol temuan.

### D-028 — Audit TLS / SH-04 (T-107, 2026-10-27)
- **ID turunan:** `SH-04.CERT` (HIGH), `SH-04.EXPIRY` (MEDIUM, < 30 hari), `SH-04.LEGACY` (MEDIUM, menerima TLS 1.0/1.1), `SH-04.HTTP` (LOW).
- **`TargetSession.tls_handshake()`** membuka koneksi TLS, menyelesaikan handshake, lalu menutupnya tanpa mengirim request HTTP. Koneksi ini tetap melewati rate limiter dan semaphore session, dan dihitung di `request_count`. Karena koneksinya langsung, fungsi ini tidak dijalankan saat memakai proxy dan hasilnya `accepted=None`.
- **Sertifikat:**
  - Tanpa `--insecure`, pre-flight sudah memverifikasi, jadi detailnya diambil dari `response.tls` tanpa koneksi tambahan.
  - Dengan `--insecure`, dilakukan satu handshake terverifikasi. Jika gagal, alasannya (`verify_message`, misalnya "self-signed certificate") masuk ke SH-04.CERT.
- **TLS lama:**
  - Dua handshake dengan `minimum_version = maximum_version = TLSv1 / TLSv1_1` dan `SECLEVEL=0`.
  - Handshake berhasil berarti diterima. Koneksi direset atau alert dari server berarti ditolak.
  - Jika OpenSSL lokal tidak mendukung (`NO_PROTOCOLS_AVAILABLE` atau context tidak bisa dibuat), hasilnya **tidak teruji** dan dicatat sebagai catatan, bukan dianggap lulus.
- **HTTP → HTTPS:**
  - Target `http://` yang tidak di-redirect: SH-04.HTTP langsung dari respons pre-flight, tanpa request tambahan.
  - Target `https://` di port 443: satu GET ke `http://host/`. Lulus jika dijawab redirect 3xx ke `https://`.
  - Cek ini dilewati jika pre-flight sudah melihat redirect http→https, atau jika HTTPS tidak di port 443. Port 80 yang tertutup hanya menjadi catatan.
- **Port 80 dianggap bagian dari target yang sama** dengan `https://host:443`, walaupun kunci otorisasi menyertakan port.

### D-029 — Kontrak plugin & loader (T-108, 2026-10-27)
- **`BasePlugin`** (`id`, `name`, `ecosystem`, `package`, `match()`, `async run(ctx)`). `match()` default-nya memakai confidence fingerprint untuk teknologi dengan `id` yang sama.
- **`ScanContext`** berisi session, baseline, URL target akhir, fingerprint, `method_probe`, dan `responses` (respons yang sudah diambil: halaman pre-flight + probe baseline), dipakai untuk cek pasif.
- **`PluginResult`** berisi findings, versions, `exposed_lockfiles` (diaudit CVE nanti di T-208), dan notes.
- **Loader `select_plugins()`:** confidence ≥ 0,8 dijalankan; 0,4–0,8 dijalankan dengan catatan; < 0,4 dilewati dengan saran memakai `--framework`. `--framework` memaksa satu plugin. Plugin yang belum ada menghasilkan catatan, bukan error.
- **Pembagian mode:**
  - `recon`: header/cookie/CORS/TLS.
  - `audit`: plugin.
  - `scan`: keduanya.
  - Semua mode dengan target URL menjalankan pre-flight, baseline, dan fingerprint.
- **`TargetRequestError` di dalam satu cek plugin** menjadi catatan, dan cek lain tetap berjalan.

### D-030 — Plugin Laravel LRV-01 s/d LRV-06 (T-109, 2026-10-27)
- **Path dan marker** ada di `data/laravel.json`. Setiap panel punya flag `verified`. Hanya marker Telescope yang sudah diverifikasi di instalasi nyata (F-014); kalau yang terkonfirmasi panel lain, confidence LRV-04 menjadi MEDIUM.
- **LRV-01:** bukti hanya **nama kunci** (`N kunci: APP_NAME, APP_KEY, ...`), tanpa nilai sama sekali. `.env.example` dengan `APP_KEY=` kosong dihitung LOW; selain itu CRITICAL.
- **LRV-02:**
  - Cek pasif dulu atas `ctx.responses`. Setelah itu `probe_patch()` (dijaga OPTIONS, D-006), kecuali `--no-method-probe`.
  - Bukti hanya berisi nama halaman debug dan versi yang bocor; isi halaman tidak disimpan.
  - Versi yang diambil dari halaman ini hanya yang bersumber `ERROR_PAGE`.
- **LRV-03:** satu GET dengan `Range: bytes=0-2047`. Bukti hanya status dan ukuran dari `Content-Range`.
- **LRV-04:** redirect tidak diikuti. 302 ke halaman login berarti aman.
- **LRV-05:**
  - `composer.json` (JSON dengan `require`) dan `composer.lock` (JSON dengan `packages`).
  - Lock file yang terekspos disimpan sebagai `ExposedLockfile`.
  - Versi `laravel/framework` dicatat dengan sumber `EXPOSED_LOCKFILE`.
- **LRV-06:** hanya `.git/HEAD` dan `.git/config`; tidak ada object yang diunduh. Bukti `config` hanya baris `url =` (kredensial dimask), karena bagian lain bisa berisi data pribadi (`user.email`).
- **Redaksi diperketat:** baris `.env` yang dikomentari (`# DB_PASSWORD=...`) sekarang juga dimask. Sebelumnya lolos; ketahuan saat plugin dijalankan terhadap target.

### D-031 — Grading & exit code (T-110, 2026-10-30)
Implementasi D-009 dan D-010 di `core/grading.py`, dengan detail yang belum ditentukan sebelumnya:
- **Severity `UNKNOWN`** (kerentanan tanpa data CVSS) diperlakukan sebagai **MEDIUM**, baik untuk penalti, batasan A+, maupun `--fail-on`. Alasannya: "kosong ≠ aman" (CLAUDE.md aturan 5).
- **Pembulatan skor** memakai half-up (`floor(x + 0.5)`), dengan batas bawah 0.
- **Kerentanan dikelompokkan** per `(component_name, ecosystem)`. Faktor dev dependency × 0,5 hanya berlaku jika **semua** kerentanan komponen itu berasal dari dependency dev.
- **Batasan A+** ("tanpa temuan MEDIUM ke atas") berlaku untuk confidence apa pun. Cap F/C hanya untuk confidence HIGH.
- **`--fail-on` menghitung temuan dengan confidence apa pun.** Ini konservatif: CVE dari banner (confidence LOW) tetap bisa menggagalkan CI. Tanpa `--fail-on`, exit code 0 walaupun ada temuan CRITICAL.
- **Scan parsial (exit code 4)** berasal dari kegagalan request di cek tertentu: probe baseline, CORS, atau cek plugin. Kegagalan plugin kini disimpan di `PluginResult.errors`, terpisah dari `notes`. Cek TLS yang "tidak teruji" karena OpenSSL lokal **tidak** membuat scan parsial.
- **Mode yang sudah lengkap: `recon` dan `audit`.** Keduanya mengembalikan exit code hasil hitungan.
  - `scan`, `cve`, dan `deps` tetap berakhir dengan exit code 2 ("belum lengkap") sampai engine CVE ada.
  - `-o/--output` tetap berakhir dengan exit code 2 tanpa menulis file sampai T-111, supaya CI tidak menganggap laporan sudah ada.

### D-032 — Reporter terminal + JSON (T-111, 2026-10-30)
- **Satu sumber data.** `build_report()` (`core/reporter/report.py`) membangun `ScanReport`, lalu reporter terminal dan JSON merender **objek yang sama**. Isinya:
  - Temuan, diurutkan berdasarkan severity lalu ID.
  - Grade dan skor, beserta `grade_caps` dan `penalties`.
  - `summary` (jumlah per severity).
  - Fingerprint, termasuk versi dari plugin (tanpa duplikat).
  - `notes` dan `errors`.
- **Field baru di `ScanReport`:** `notes`, `grade_caps`, `penalties` (`ScorePenalty`), dan `summary`. `report_schema` tetap `"1.0"` karena belum pernah dirilis.
- **Laporan JSON tidak pernah memuat body respons mentah atau isi lock file.** `ExposedLockfile.content` sengaja tidak masuk laporan. Evidence sudah diredaksi saat dibuat.
- **File ditulis atomik** (tmp lalu replace), folder induk dibuat otomatis. Laporan tetap ditulis walau exit code 1 (`--fail-on`), karena justru saat itu laporannya dibutuhkan CI.
- **Format `.md`/`.html` ditolak sebelum scan dimulai** (exit code 2, tanpa request), daripada baru gagal setelah scan penuh. Didukung nanti di T-306/T-307.
- **Gagal pre-flight (exit code 3) tidak menghasilkan file laporan.**

### D-023 — Konvensi commit (2026-10-27, permintaan pemilik produk)
Gaya Conventional Commits (`feat:`, `update:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`), tanpa label fase. Judul dan body ditulis dalam bahasa Indonesia. Detail ada di CLAUDE.md.

### D-021 — Banner CLI (2026-10-27)
Banner ASCII dari pemilik produk disimpan apa adanya di `shound/data/banner.txt`. Satu-satunya perubahan: `v1.0.0` diganti placeholder `v{version}`, yang diisi `__version__` (D-013). Dipakai di T-102.

## Fakta teknis

- **F-001 — NVD `isVulnerable`.** Tanpa parameter ini, query `cpeName` juga mengembalikan CVE aplikasi lain yang hanya *berjalan di atas* komponen tersebut (misalnya ratusan aplikasi PHP). Hasil NVD juga harus di-paginate (`resultsPerPage` maksimal 2000, `startIndex`).
- **F-002 — NVD `cpeName` harus ada di CPE Dictionary.** Jika tidak ada, hasilnya kosong, dan itu bukan berarti aman. Cek dulu lewat `/rest/json/cpes/2.0`, fallback ke `virtualMatchString`.
- **F-003 — nginx punya dua vendor CPE**: `nginx:nginx` (CVE lama) dan `f5:nginx` (CVE baru). Query keduanya.
- **F-004 — Kenapa debug mode Laravel bocor lewat 405.** Laravel tidak punya view error 405 bawaan (hanya 401, 402, 403, 404, 419, 429, 500, 503). Karena itu `MethodNotAllowedHttpException` di debug mode dirender oleh Ignition. Untuk OPTIONS yang tidak punya route, router Laravel otomatis menjawab dengan header `Allow`.
- **F-005 — `XSRF-TOKEN` Laravel sengaja tidak HttpOnly** karena dibaca JavaScript (axios). Jangan dilaporkan di SH-02 untuk HttpOnly. Nama cookie ini juga dipakai Angular, jadi bobot fingerprint-nya kecil.
- **F-006 — OSV tidak memberi skor numerik.** `severity[].score` berisi vector CVSS. Fallback ke `database_specific.severity` (GHSA memakai `MODERATE` = MEDIUM).
- **F-007 — Satu advisory OSV bisa punya beberapa range per cabang** (8.x / 9.x / 10.x). `fixed_version` harus diambil dari interval yang memuat versi terdeteksi.
- **F-008 — Respons OSV `querybatch` hanya berisi ID**, dengan `next_page_token` per query. Detail diambil via `/v1/vulns/{id}` setelah ID dideduplikasi.
- **F-009 — Banner versi distro sering di-backport** (misalnya `Apache/2.4.41 (Ubuntu)`). CVE NVD dari banner yang memuat token distro diberi confidence LOW.
- **F-010 — Format lock file.** `composer.lock` punya `packages` dan `packages-dev`; versi berprefiks `v`; versi `dev-*` tidak bisa diaudit. `package-lock.json` v1 memakai `dependencies`, sedangkan v2/v3 memakai `packages` dengan key `node_modules/...`. `requirements.txt` hanya bisa diaudit untuk pin `==`.
- **F-011 — Pydantic v2:** `Optional[X]` tanpa default tetap wajib diisi.
- **F-012 — Batas rate NVD:** 5 request / 30 detik tanpa API key, 50 request / 30 detik dengan key.
- **F-013 — Nama cookie session Laravel tidak tetap.** Namanya diturunkan dari `APP_NAME`:
  - Laravel ≤ 10: `<slug>_session` (contoh `laravel_session`).
  - Laravel ≥ 11: `<slug>-session` (contoh `laravel-session`).

  Sinyal yang lebih andal adalah nilainya: semua cookie terenkripsi Laravel (session dan `XSRF-TOKEN`) diawali `eyJpdiI6`, yaitu base64 dari `{"iv":`. Diverifikasi di target Docker. **Berbeda dari PRD §3.2.1**, yang hanya menyebut `laravel_session`.
- **F-014 — Telescope 5 meng-inline JS/CSS-nya.** Tidak ada `/vendor/telescope/app.js`, dan halamannya sekitar 1,8 MB, lebih besar dari batas body 1 MiB. Signature yang terbukti ada di awal halaman: `<title>Telescope - Laravel</title>` dan `window.Telescope =`. **Berbeda dari PRD LRV-04.**
- **F-015 — Halaman debug Laravel ≥ 11 bukan Ignition**, melainkan renderer bawaan Laravel. Markernya `MethodNotAllowedHttpException`, `## Stack Trace`, dan `Copy as Markdown`. Versi bocor dalam blok markdown yang di-escape JSON (`\nPHP 8.3.36\nLaravel 12.70.1`); karena diawali `\n`, regex tidak boleh memakai `\b`.
  Laravel 10 (Ignition) membocorkan `"laravel_version":"10.50.3"` dan `"php_version":"…"`, dengan marker `spatie/laravel-ignition` dan `window.ignite`.
  **PRD LRV-02 baru mencantumkan marker Ignition/Whoops.**
- **F-017 — `sys.stdin.isatty()` tidak bisa dipercaya di Windows.** Hasilnya `True` untuk device `NUL` dan untuk mintty (Git Bash), padahal prompt_toolkit crash di keduanya (`NoConsoleScreenBufferError`). `prompts.is_interactive_terminal()` karena itu juga memeriksa `GetConsoleMode` pada handle stdin.
- **F-018 — questionary `Choice(value=None)` mengembalikan judulnya, bukan `None`.** Untuk pilihan "Kembali", gunakan nilai eksplisit (misalnya `"back"`) lalu petakan ke `None`.
- **F-019 — `OPENSSL_CONF` di mesin dev** menunjuk ke file PostgreSQL yang tidak ada, sehingga `openssl req` gagal. Test TLS lokal karena itu memakai config OpenSSL minimal miliknya sendiri dan menghapus variabel tersebut dari environment subprocess.
- **F-020 — httpcore menyediakan extension `network_stream` untuk HTTP/1.1 maupun HTTP/2.** Dengan `get_extra_info("ssl_object")`, objek SSL koneksi bisa dibaca saat respons di-stream.
- **F-021 — Dengan `verify_mode=CERT_NONE` (`--insecure`), `getpeercert()` mengembalikan `{}`.** Subject, issuer, dan tanggal kedaluwarsa tidak tersedia tanpa library parser X.509 tambahan.
- **F-022 — Python 3.11 + OpenSSL 3.0.13 (Windows) masih bisa handshake TLS 1.0/1.1**, asalkan `set_ciphers("DEFAULT:@SECLEVEL=0")`. Server yang menolak biasanya memutus koneksi (`ConnectionResetError`), bukan mengirim alert. Python mengeluarkan `DeprecationWarning` untuk `TLSVersion.TLSv1`/`TLSv1_1`, yang di-suppress di `_handshake_context`.
- **F-016 — `OPTIONS /` di Laravel membalas `Allow: GET,HEAD`** (tanpa spasi). Guard `probe_patch()` bekerja di Laravel 10 dan 12, dan PATCH mengembalikan 405 dengan halaman debug.
