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
  | sudo bash -s -- \
      --domain  hermes.dyit.de \
      --api-host certs.dyit.de
```

Der Installer braucht **nur zwei Angaben**: die eigene Domain (für die das
Zertifikat bestimmt ist) und den Hostnamen des `cert-api`-Servers. Daraus
baut er automatisch:

1. `api_url = "https://${api-host}"`
2. `target_dir = "/etc/ssl/${domain}"`
3. einen frischen 64-Zeichen-Hex-`api_key` – den gibst du dem
   `cert-api`-Admin, damit er die Domain damit registriert
4. einen passenden `[[certificates]]`-Block in `cert-sync.toml`
5. (falls nginx installiert ist) ein vorkonfiguriertes
   `/etc/nginx/conf.d/${domain}.conf` mit SSL-Pfaden und einer
   `proxy_pass`-Zeile als Platzhalter – **diese musst du noch anpassen**
   (s. u.)
6. `/etc/cron.d/cert-sync` mit Default-Zeit `03:17` und Log nach
   `/var/log/cert-sync.log`

`api_key` und `reload_cmd` werden **nicht** als Parameter abgefragt: der
Installer generiert beides selbst. Pro Host reicht ein Eintrag – soll der
selbe Host ein zweites Zertifikat ziehen, `[[certificates]]`-Block in
`cert-sync.toml` manuell ergänzen.

## Optionen

Beide Skripte akzeptieren Argumente nach `bash -s --`, z. B.:

```bash
curl -fsSL …/install-cert-api.sh | sudo bash -s -- --version v0.2.0 --no-nginx
curl -fsSL …/install-cert-sync.sh | sudo bash -s -- --no-nginx --cron-time "47 4 * * *"
```

`--help` listet jeweils alle Optionen. Mit `--uninstall` wird wieder alles
entfernt, was das Skript angelegt hat (inkl. zugehöriger nginx-Snippets).

## Beispiel: `hermes.dyit.de` von Anfang bis Ende

**1. Server-Seite** (auf dem Host, der `cert-api` ausführt – in der Regel der
Host, auf dem certbot läuft):

```bash
curl -fsSL …/install-cert-api.sh | sudo bash
sudo /usr/local/share/cert-api/add-cert.sh -c /etc/cert-api/config.toml hermes.dyit.de
#   Name:     hermes.dyit.de
#   API-Key:  <64-Zeichen-Hex>           ← notieren / sicher ablegen!
```

**2. Client-Seite** (auf jedem Host, der das Zertifikat braucht). Den
notierten API-Key als `api_key` auf der Server-Seite registrieren – den hier
vom Client-Installer erzeugten Key dem Server-Admin geben (Reverse-Richtung):

```bash
curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-sync.sh \
  | sudo bash -s -- \
      --domain   hermes.dyit.de \
      --api-host certs.dyit.de
#  → Konfiguration generiert: /etc/cert-sync/cert-sync.toml
#  → API-Key (dem cert-distributor-Admin geben, damit er 'hermes.dyit.de' damit registriert):
#     8e45ac82a31b9c8e578bd402fa09d4c94416d37ef2ac09c9202efac951d7de9c

sudo cert-sync --check-only    # exit 0 oder 1 → ok, exit 2 → Config prüfen
```

**3. Reverse-Proxy / Backend** – der Installer legt bei installiertem nginx
eine Datei `/etc/nginx/conf.d/hermes.dyit.de.conf` mit SSL-Block und einem
Platzhalter an. Den musst du noch auf dein eigentliches Backend zeigen
lassen:

```nginx
server {
    listen 443 ssl;
    server_name hermes.dyit.de;

    ssl_certificate     /etc/ssl/hermes.dyit.de/fullchain.pem;
    ssl_certificate_key /etc/ssl/hermes.dyit.de/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;   # <-- anpassen
    }
}
```

`proxy_pass http://127.0.0.1:8080;` zeigt standardmäßig auf Port 8080 –
ersetzen durch deinen App-Server (oder `unix:/var/run/app.sock`, anderer
Port etc.), dann `nginx -t && systemctl reload nginx`.

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
