# Installer

Zwei Einzeiler – einen für den Server (`cert-api`), einen für den Client
(`cert-sync`). Beide Skripte liegen zusätzlich als `install-cert-api.sh` und
`install-cert-sync.sh` in diesem Verzeichnis, damit man sie vorher lesen kann.

> Die Skripte brauchen `root` und passen `/usr/local/bin`, `/etc/cert-api` bzw.
> `/etc/cert-sync`, die Gruppe `ssl-cert` und Lets-Encrypt-Pfade an. Idempotent
> (erneut laufen lassen = keine Doppel-Arbeit). Mit `--uninstall` räumt sich
> alles wieder auf.

## Server (`cert-api`) installieren

```bash
curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-api.sh \
  | sudo bash
```

Was passiert:

1. passendes Release-Asset für die erkannte Architektur (`x86_64`, `arm64`,
   `armv7`) wird geladen und per SHA-256 verifiziert
2. `cert-api` landet in `/usr/local/bin`
3. System-Benutzer `cert-api` und Gruppe `ssl-cert` werden angelegt (falls
   fehlend); `cert-api` wird Mitglied von `ssl-cert`
4. Lets-Encrypt-Pfade (`/etc/letsencrypt/live` und `/etc/letsencrypt/archive`)
   bekommen Gruppen-Leserechte; `privkey.pem` wird zusätzlich `g+r` für die
   Gruppe gesetzt
5. `/etc/cert-api` (`750`, Gruppe `cert-api`) und eine leere `config.toml`
   (`600`) entstehen
6. systemd-Unit `cert-api.service` wird installiert, aktiviert und gestartet
7. nginx-Vorlage wird unter `/etc/cert-api/nginx/cert-api.conf` abgelegt

Danach ein Zertifikat samt API-Key eintragen:

```bash
curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/scripts/add-cert.sh \
  | sudo bash -s -- -c /etc/cert-api/config.toml example.com
# ausgegebenen API-Key notieren → landet in der Client-Config
```

## Client (`cert-sync`) installieren

```bash
curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-sync.sh \
  | sudo bash
```

Was passiert:

1. Release-Asset laden, SHA-256 prüfen, Binary nach `/usr/local/bin/cert-sync`
2. `/etc/cert-sync` (`700`) und `/etc/cert-sync/cert-sync.toml` (`600`,
   Platzhalter) anlegen
3. `/etc/cron.d/cert-sync` mit Default-Zeit `03:17` und Log nach
   `/var/log/cert-sync.log`

Danach in der TOML `api_url` und pro Zertifikat `name`, `api_key`,
`target_dir`, ggf. `reload_cmd` eintragen und Probelauf:

```bash
sudo -e /etc/cert-sync/cert-sync.toml   # oder Lieblingseditor
sudo cert-sync --check-only              # muss exit 0 oder 1 liefern, kein 2
```

## Optionen

Beide Skripte akzeptieren Argumente nach `bash -s --`, z. B.:

```bash
curl -fsSL …/install-cert-api.sh | sudo bash -s -- --version v0.2.0 --no-nginx
curl -fsSL …/install-cert-sync.sh | sudo bash -s -- --cron-time "47 4 * * *"
```

`--help` listet jeweils alle Optionen. Mit `--uninstall` wird wieder alles
entfernt, was das Skript angelegt hat.

## Beispiel: `hermes.dyit.de` von Anfang bis Ende

**1. Server-Seite** (auf dem Host, der `cert-api` ausführt – in der Regel der
Host, auf dem certbot läuft):

```bash
curl -fsSL …/install-cert-api.sh | sudo bash
sudo /usr/local/share/cert-api/add-cert.sh -c /etc/cert-api/config.toml hermes.dyit.de
#   Name:     hermes.dyit.de
#   API-Key:  <64-Zeichen-Hex>           ← notieren / sicher ablegen!
```

**2. Client-Seite** (auf jedem Host, der das Zertifikat braucht). Den notierten
API-Key einsetzen, in Hochkomma – Sonderzeichen behält die Shell so sicher:

```bash
API_KEY="<hier_den_von_add-cert.sh_ausgegebenen_key_einsetzen>"
curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-sync.sh \
  | sudo bash -s -- \
      --api-url https://certs.dyit.de \
      --cert    "hermes.dyit.de:${API_KEY}:/etc/ssl/hermes.dyit.de:nginx -t && systemctl reload nginx"
sudo cert-sync --check-only              # exit 0 oder 1 → ok, exit 2 → Config prüfen
```

Was dadurch automatisch passiert: `cert-sync.toml` wird mit `api_url` und
genau einem `[[certificates]]`-Block für `hermes.dyit.de` (inkl.
`reload_cmd`) angelegt, der Cronjob steht ab morgen 03:17 in
`/etc/cron.d/cert-sync`, Log unter `/var/log/cert-sync.log`.

**3. Reverse-Proxy** – das war's noch nicht, der Client zeigt via HTTPS auf
die nginx-Frontseite des Servers. Diese Config-Schnipsel sind unabhängig; in
den `server { … }`-Block für `certs.dyit.de` gehört ein

```nginx
location / {
    limit_req zone=certapi burst=20 nodelay;
    proxy_pass http://127.0.0.1:8443;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

(Vorlage liegt nach der Server-Installation bereits unter
`/etc/cert-api/nginx/cert-api.conf`.)

## Release-Schema

Seit [ci/split-releases-coverage](https://github.com/gualcoinus/cert-distributor/tree/ci/split-releases-coverage)
werden pro Architektur **zwei** Tarballs veröffentlicht:

| Tarball | Inhalt |
|---|---|
| `cert-api-<TAG>-<ARCH>.tar.gz`    | `cert-api`, `deploy/cert-api.service`, Beispiel-Config, `scripts/add-cert.sh` |
| `cert-sync-<TAG>-<ARCH>.tar.gz`   | `cert-sync`, ggf. `scripts/cert-sync.sh`, Beispiel-Config, Cron-Beispiel |

`<ARCH>` ∈ {`linux-x86_64`, `linux-arm64`, `linux-armv7`}. Pro Tarball liegt
jeweils eine `.sha256`-Datei daneben. `install-cert-api.sh` lädt nur den
Server-, `install-cert-sync.sh` nur den Client-Tarball.

## Wenn man doch erst lesen will

```bash
curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-api.sh -o install-cert-api.sh
less install-cert-api.sh
sudo bash install-cert-api.sh
```

## Voraussetzungen

- Linux (`uname -m` = `x86_64`, `aarch64` oder `armv7l`) – die Releases sind
  statisch gegen musl gelinkt, keine Abhängigkeiten außer den mitgelieferten
  Tools (`curl`, `tar`, `openssl`, `sha256sum`)
- systemd und (optional) nginx
- Lets-Encrypt-Zertifikate unter `/etc/letsencrypt/{live,archive}` – andere
  Pfade per `--live` / `--archive` übergeben
