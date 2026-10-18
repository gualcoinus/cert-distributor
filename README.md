# cert-distributor

Verteilt Let's-Encrypt-Zertifikate per REST-API an andere Server – jedes Zertifikat mit eigenem API-Key.

- **`cert-api`** (Server): lauscht auf `127.0.0.1`, TLS macht nginx davor. Liefert aktuelle und abgelaufene Zertifikate und kann per Fingerprint prüfen, ob es ein neueres gibt.
- **`cert-sync`** (Client, Rust): per Cron täglich ausführen. Prüft, lädt, validiert, tauscht atomar aus, lädt den Dienst neu (mit Rollback).
- **`scripts/`**: `add-cert.sh` trägt eine neue Domain samt API-Key in die Server-Config ein; `cert-sync.sh` ist eine Bash-Alternative zum Rust-Client.

```
 certbot ──► /etc/letsencrypt ──► cert-api (127.0.0.1) ──► nginx (TLS) ──► cert-sync ──► nginx/postfix/… reload
```

## API

Authentifizierung per `X-API-Key: …` oder `Authorization: Bearer …`. Der Key gilt nur für das Zertifikat in der URL.

| Endpunkt | Zweck |
|---|---|
| `GET /health` | Health-Check (ohne Key) |
| `GET /v1/certs/{name}/check?fingerprint=<sha256-hex>` | Gibt es ein neues Zertifikat? |
| `GET /v1/certs/{name}/info` | Subject, SANs, Seriennummer, Fingerprint, Gültigkeit |
| `GET /v1/certs/{name}/files/{file}` | `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem` (aktuell) |
| `GET /v1/certs/{name}/bundle` | Alle aktuellen Dateien + Info als JSON |
| `GET /v1/certs/{name}/archive` | Alle Versionen inkl. abgelaufener |
| `GET /v1/certs/{name}/archive/{file}` | z. B. `fullchain2.pem` |

## Server einrichten

```bash
# Binary aus dem Release nach /usr/local/bin, dann:
install -d -m 700 /etc/cert-api
./scripts/add-cert.sh -c /etc/cert-api/config.toml -r cert-api example.com   # gibt den API-Key aus
cp deploy/cert-api.service /etc/systemd/system/ && systemctl enable --now cert-api
# nginx: cert-api/nginx.conf.example
```

`config.toml`:

```toml
listen = "127.0.0.1:8443"          # muss Loopback sein

[[certificates]]
name = "example.com"
api_key = "…mind. 32 Zeichen…"      # openssl rand -hex 32
live_path = "/etc/letsencrypt/live/example.com"
archive_path = "/etc/letsencrypt/archive/example.com"   # optional
```

Die Zertifikate werden bei jeder Anfrage von der Platte gelesen – nach einer Erneuerung ist das neue Zertifikat sofort verfügbar. Die Config wird nur beim Start gelesen.

## Client einrichten

```bash
install -d -m 700 /etc/cert-sync
install -m 600 examples/cert-sync.example.toml /etc/cert-sync/cert-sync.toml   # anpassen
cert-sync --check-only          # Probelauf
cp examples/cert-sync.cron.example /etc/cron.d/cert-sync                       # täglich 03:17
```

Optionen: `--check-only`, `--force`, `--only <name>`, `-c <config>`. Exit-Codes: `0` ok, `1` mind. ein Zertifikat fehlgeschlagen, `2` Config-/Startfehler.

## Releases

Ein Tag `vX.Y.Z` löst den Release-Workflow aus (Tests + Coverage-Gate, dann Build, dann GitHub Release mit Prüfsummen). Pro Tag und Zielarchitektur entstehen zwei Tarballs:

| Datei | Inhalt |
|---|---|
| `cert-api-${TAG}-linux-x86_64.tar.gz` | Server-Binary + `cert-api.service` + `add-cert.sh` + Beispiel-Configs |
| `cert-api-${TAG}-linux-arm64.tar.gz` | dito für aarch64 |
| `cert-api-${TAG}-linux-armv7.tar.gz` | dito für armv7 (Raspberry Pi 4 mit 32-Bit-OS) |
| `cert-sync-${TAG}-linux-x86_64.tar.gz` | Client-Binary + Beispiel-Configs + `cert-sync.sh` + Crons |
| `cert-sync-${TAG}-linux-arm64.tar.gz` | dito für aarch64 |
| `cert-sync-${TAG}-linux-armv7.tar.gz` | dito für armv7 |

Die Binaries sind statisch gegen musl gelinkt und laufen unabhängig von der glibc-Version des Zielsystems.

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Entwicklung

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo llvm-cov --workspace --all-features --summary-only --fail-under-lines 75
```

CI (`.github/workflows/ci.yml`) führt Format-Check, Clippy, Tests, Coverage-Gate (>= 75 % Lines), ShellCheck und einen Cross-Build für ARM (aarch64 + armv7) bei jedem Push und Pull Request aus. Die Dateien in `testdata/` sind reine Test-Fixtures (selbstsigniert, ohne Bedeutung). Die Coverage-Schwelle ist als Actions-Variable `COVERAGE_THRESHOLD` konfigurierbar.

## Sicherheit

- Echte Konfigurationen enthalten API-Keys: `chmod 600`, nie committen (`.gitignore` schützt davor).
- Der Server-Dienst braucht Lesezugriff auf `/etc/letsencrypt/live` und `archive` – besser über eine Gruppe als als root.
- Die API verteilt **private Schlüssel**: nur über TLS (nginx), idealerweise zusätzlich per IP einschränken.
- API-Keys werden mit konstanter Laufzeit verglichen; falscher Key und unbekannter Name liefern dieselbe 401-Antwort.
