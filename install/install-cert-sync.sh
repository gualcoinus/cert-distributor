#!/usr/bin/env bash
# install-cert-sync.sh – Installer für den cert-sync-Client (gualcoinus/cert-distributor)
#
# Aufruf (typisch, kopieren & einfügen):
#   curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-sync.sh \
#     | sudo bash -s -- --domain hermes.dyit.de --api-host certs.dyit.de
#
# Pflicht-Argumente, wenn cert-sync.toml NEU generiert werden soll:
#   --domain   hermes.dyit.de    Eigene Domain (= Cert-Name + Default-Target)
#   --api-host certs.dyit.de     Hostname des cert-distributor-Servers.
#                                api_url wird daraus als "https://${api-host}" gebaut.
#
# Optionale Argumente (nach `bash`, durch -- getrennt):
#   --version   vX.Y.Z          statt neuestem Release
#   --repo      OWNER/REPO      Default: gualcoinus/cert-distributor
#   --bin-dir   /usr/local/bin
#   --conf-dir  /etc/cert-sync
#   --bin-name  cert-sync       Alternativer Binary-Name (z. B. cert-sync-bash)
#   --target-dir /etc/ssl/hermes.dyit.de   Default: /etc/ssl/${domain}
#   --no-nginx                  nginx-Snippet nicht mitanlegen (sonst Default)
#   --no-cron                   Cronjob nicht anlegen
#   --cron-time "17 3 * * *"    Standard: 03:17 täglich
#   --dry-run                   cert-sync.toml nur ablegen, nicht ausführen
#   --uninstall
#   -h | --help
set -Eeuo pipefail

REPO="gualcoinus/cert-distributor"
VERSION=""
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/cert-sync"
BIN_NAME="cert-sync"
DOMAIN=""                            # Eigene Domain (Cert-Name + Default-Target)
API_HOST=""                          # cert-distributor-Host  -> api_url = https://${API_HOST}
TARGET_DIR_OPT=""                    # expliziter Override, sonst /etc/ssl/${DOMAIN}
DO_NGINX=1                           # nginx-Snippet anlegen, wenn nginx installiert
DO_CRON=1
CRON_TIME="17 3 * * *"
DO_DRYRUN=0
DO_UNINSTALL=0

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)     VERSION="$2";     shift 2 ;;
    --repo)        REPO="$2";        shift 2 ;;
    --bin-dir)     BIN_DIR="$2";     shift 2 ;;
    --conf-dir)    CONF_DIR="$2";    shift 2 ;;
    --bin-name)    BIN_NAME="$2";    shift 2 ;;
    --domain)      DOMAIN="$2";      shift 2 ;;
    --api-host)    API_HOST="$2";    shift 2 ;;
    --target-dir)  TARGET_DIR_OPT="$2"; shift 2 ;;
    --no-nginx)    DO_NGINX=0;       shift ;;
    --no-cron)     DO_CRON=0;        shift ;;
    --cron-time)   CRON_TIME="$2";   shift 2 ;;
    --dry-run)     DO_DRYRUN=1;      shift ;;
    --uninstall)   DO_UNINSTALL=1;   shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Dieses Skript braucht root-Rechte (sudo)." >&2; exit 1
fi
for bin in curl tar awk grep sha256sum openssl; do
  command -v "$bin" >/dev/null || { echo "'$bin' wird benötigt" >&2; exit 1; }
done

API_REPO="https://api.github.com/repos/${REPO}"
# Asset-Downloads liegen unter github.com (api.github.com antwortet mit 404),
# die curl mit -L automatisch auf den Azure-CDN-Endpunkt weiterleitet.
DOWNLOAD_BASE="https://github.com/${REPO}"

detect_arch() {
  case "$(uname -m)" in
    x86_64)  echo "linux-x86_64" ;;
    aarch64) echo "linux-arm64"   ;;
    armv7l)  echo "linux-armv7"   ;;
    *)
      echo "Nicht unterstützte Architektur: $(uname -m)" >&2; exit 1 ;;
  esac
}
resolve_version() {
  if [[ -n $VERSION ]]; then echo "$VERSION"; return; fi
  local tag
  tag="$(curl -fsSL "$API_REPO/releases/latest" | awk -F'"' '/"tag_name":/{print $4; exit}')"
  [[ -n $tag ]] || { echo "Konnte neuestes Release nicht ermitteln – --version angeben." >&2; exit 1; }
  echo "$tag"
}

if (( DO_UNINSTALL )); then
  rm -f /etc/cron.d/cert-sync
  rm -f "$BIN_DIR/$BIN_NAME"
  rm -rf "$CONF_DIR"
  # Zugehoerige nginx-Snippets aus /etc/nginx/conf.d/<domain>.conf mit entfernen,
  # sofern sie nachweislich von diesem Installer stammen (Kommentar-Marker).
  if [[ -d /etc/nginx/conf.d ]]; then
    for f in /etc/nginx/conf.d/*.conf; do
      [[ -f $f ]] || continue
      if head -1 "$f" 2>/dev/null | grep -q '^# Generiert von install-cert-sync.sh'; then
        echo "Loesche nginx-Snippet: $f"
        rm -f "$f"
      fi
    done
  fi
  echo "cert-sync deinstalliert (Log unter /var/log/cert-sync.log bleibt bestehen)."
  exit 0
fi

ARCH="$(detect_arch)"
TAG="$(resolve_version)"
ASSET="cert-sync-${TAG}-${ARCH}.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Lade $ASSET"
curl -fsSL -o "$TMP/$ASSET"             "$DOWNLOAD_BASE/releases/download/$TAG/$ASSET"
curl -fsSL -o "$TMP/$ASSET.sha256"      "$DOWNLOAD_BASE/releases/download/$TAG/$ASSET.sha256"
( cd "$TMP" && sha256sum -c "$ASSET.sha256" )

tar -xzf "$TMP/$ASSET" -C "$TMP"
PKG_DIR="$(find "$TMP" -maxdepth 1 -type d -name "cert-sync-${TAG}-${ARCH}" | head -n1)"

install -m 0755 "$PKG_DIR/cert-sync" "$BIN_DIR/$BIN_NAME"
# alternativer Bash-Client aus dem selben Paket
if [[ -f $PKG_DIR/scripts/cert-sync.sh ]]; then
  install -m 0755 "$PKG_DIR/scripts/cert-sync.sh" "$BIN_DIR/cert-sync.sh"
elif [[ -f $PKG_DIR/cert-sync.sh ]]; then
  install -m 0755 "$PKG_DIR/cert-sync.sh" "$BIN_DIR/cert-sync.sh"
fi

# Config-Verzeichnis mit restriktiven Rechten (frueh anlegen, damit die
# Cron-Beispiele darunter abgelegt werden koennen).
install -d -m 0700 -o root -g root "$CONF_DIR"

# Cron-Beispiele aus dem Paket ablegen. Im neuen Split-Tarball liegen beide
# Varianten unter unterschiedlichen Namen: cert-sync.cron.example (Rust)
# und cert-sync.sh.cron.example (Bash-Alternative).
if [[ -f $PKG_DIR/cert-sync.cron.example ]]; then
  install -m 0644 "$PKG_DIR/cert-sync.cron.example" "$CONF_DIR/cert-sync.cron.example"
fi
if [[ -f $PKG_DIR/cert-sync.sh.cron.example ]]; then
  install -m 0644 "$PKG_DIR/cert-sync.sh.cron.example" "$CONF_DIR/cert-sync.sh.cron.example"
fi
# Legacy-Pfad: alte Releases hatten das Beispiel unter scripts/.
if [[ -f $PKG_DIR/scripts/cert-sync.cron.example ]]; then
  install -m 0644 "$PKG_DIR/scripts/cert-sync.cron.example" "$CONF_DIR/cert-sync.cron.example"
fi

CONFIG="$CONF_DIR/cert-sync.toml"
GENERATED_API_KEY=""                 # wird beim Schreiben gesetzt, am Ende ausgegeben
write_config() {
  # $1 = api_url, $2 = name, $3 = target_dir, $4 = api_key
  ( umask 077
    {
      printf '# cert-sync-Konfiguration – generiert von install-cert-sync.sh\n'
      printf '#   domain   : %s\n' "$2"
      printf '#   api_url  : %s\n' "$1"
      printf '#   target   : %s\n' "$3"
      printf '\n'
      printf 'api_url    = "%s"\n' "$1"
      printf 'reload_cmd = "nginx -t && systemctl reload nginx"\n'
      printf '\n'
      printf '[[certificates]]\n'
      printf 'name       = "%s"\n' "$2"
      printf 'api_key    = "%s"\n' "$4"
      printf 'target_dir = "%s"\n' "$3"
    } > "$CONFIG"
  )
  chmod 600 "$CONFIG"
}

# Plausibilitaet der Parameter
if [[ -n $DOMAIN && -z $API_HOST ]] || [[ -z $DOMAIN && -n $API_HOST ]]; then
  echo "Optionen --domain und --api-host muessen zusammen angegeben werden." >&2
  exit 2
fi
if [[ -n $DOMAIN ]]; then
  # Sanity-Check: nur erlaubte Zeichen, damit wir keine Pfad-Traversal o.ae. zulassen
  if [[ ! $DOMAIN =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Ungueltiger Domain-Wert: '$DOMAIN' (nur A-Z a-z 0-9 . _ - erlaubt)" >&2
    exit 2
  fi
fi
if [[ -n $API_HOST ]]; then
  if [[ ! $API_HOST =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Ungueltiger --api-host-Wert: '$API_HOST' (nur A-Z a-z 0-9 . _ - erlaubt)" >&2
    exit 2
  fi
fi

if [[ ! -f $CONFIG ]]; then
  if [[ -n $DOMAIN && -n $API_HOST ]]; then
    # Eigene Config generieren
    local_api_url="https://${API_HOST}"
    local_target="${TARGET_DIR_OPT:-/etc/ssl/${DOMAIN}}"
    # 32 Byte hex = 64 Zeichen, erfuellt das cert-api-Mindestmass von 32 Zeichen.
    GENERATED_API_KEY="$(openssl rand -hex 32)"
    write_config "$local_api_url" "$DOMAIN" "$local_target" "$GENERATED_API_KEY"
    echo "Konfiguration generiert: $CONFIG"
  else
    # Fallback: unverändertes Beispiel aus dem Release-Tarball, Nutzer trägt selbst nach.
    if [[ -f $PKG_DIR/cert-sync/cert-sync.example.toml ]]; then
      install -m 0600 "$PKG_DIR/cert-sync/cert-sync.example.toml" "$CONFIG"
    elif [[ -f $PKG_DIR/examples/cert-sync.example.toml ]]; then
      install -m 0600 "$PKG_DIR/examples/cert-sync.example.toml" "$CONFIG"
    else
      curl -fsSL -o "$CONFIG" \
        "https://raw.githubusercontent.com/${REPO}/main/cert-sync/cert-sync.example.toml"
      chmod 600 "$CONFIG"
    fi
    echo "Beispiel-Config abgelegt: $CONFIG  (jetzt anpassen: domain + api_host angeben und neu aufrufen)"
  fi
elif [[ -n $DOMAIN || -n $API_HOST ]]; then
  echo "Hinweis: $CONFIG existiert bereits – --domain/--api-host werden ignoriert." >&2
  echo "         Bestehende Config wird weiter genutzt. 'sudo $BIN_NAME --check-only' zum Testen." >&2
fi

# --- nginx-Konfiguration (optional, nur wenn nginx installiert) --------------
if (( DO_NGINX )) && [[ -n $DOMAIN ]] && command -v nginx >/dev/null && [[ -d /etc/nginx ]]; then
  NGINX_DIR="/etc/nginx/conf.d"
  install -d -m 0755 "$NGINX_DIR"
  NGINX_CONF="$NGINX_DIR/${DOMAIN}.conf"
  if [[ -f $NGINX_CONF ]]; then
    echo "Hinweis: $NGINX_CONF existiert bereits – wird nicht ueberschrieben." >&2
  else
    target_dir="${TARGET_DIR_OPT:-/etc/ssl/${DOMAIN}}"
    cat >"$NGINX_CONF" <<EOF
# Generiert von install-cert-sync.sh – bitte anpassen (insbesondere proxy_pass).
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     ${target_dir}/fullchain.pem;
    ssl_certificate_key ${target_dir}/privkey.pem;

    # TODO: Wohin soll nginx proxyn? Platzhalter anpassen.
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
EOF
    chmod 0644 "$NGINX_CONF"
    echo "nginx-Snippet angelegt: $NGINX_CONF (proxy_pass anpassen!)"
    if nginx -t 2>/dev/null; then
      echo "nginx -t: OK"
    else
      echo "WARN: nginx -t meldet einen Fehler – bitte ${NGINX_CONF} pruefen." >&2
    fi
  fi
elif (( DO_NGINX )) && [[ -n $DOMAIN ]] && ! command -v nginx >/dev/null; then
  echo "nginx nicht installiert – kein Snippet angelegt (cert + key in ${TARGET_DIR_OPT:-/etc/ssl/${DOMAIN}} sind trotzdem da)."
fi

# Cronfile: nur anlegen, wenn /etc/cron.d existiert (vom cron-Daemon gelesen,
# nicht von systemd – systemctl als Voraussetzung zu pruefen war falsch und
# hat in containerisierten Umgebungen (Actions, Docker) den Cronjob
# stillschweigend weggelassen).
if (( DO_CRON )) && [[ -d /etc/cron.d ]]; then
  cat >/etc/cron.d/cert-sync <<EOF
# cert-sync – zieht aktuelle Let's-Encrypt-Zertifikate vom cert-api-Server
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
$CRON_TIME root $BIN_DIR/$BIN_NAME -c $CONFIG >> /var/log/cert-sync.log 2>&1
EOF
  chmod 0644 /etc/cron.d/cert-sync
  touch /var/log/cert-sync.log && chmod 0640 /var/log/cert-sync.log
  echo "Cronjob: $CRON_TIME  ($BIN_DIR/$BIN_NAME -c $CONFIG)"
fi

if (( DO_DRYRUN )); then
  echo "--dry-run: führe $BIN_NAME --check-only nicht aus."
else
  echo "==> Probelauf"
  if "$BIN_DIR/$BIN_NAME" --check-only -c "$CONFIG"; then
    echo "Erreichbar – nichts zu erneuern oder Konfiguration unvollständig (siehe Log)."
  else
    rc=$?
    echo "Hinweis: cert-sync lieferte Exit $rc – das ist beim Erstaufruf ohne API-Daten normal."
  fi
fi

cat <<EOF

==> Fertig.
   Binary : $BIN_DIR/$BIN_NAME
   Config : $CONFIG
   Log    : /var/log/cert-sync.log
   Cron   : /etc/cron.d/cert-sync
EOF

if [[ -n $GENERATED_API_KEY ]]; then
  cat <<EOF

   Domain  : $DOMAIN
   api_url : https://${API_HOST}
   target  : ${TARGET_DIR_OPT:-/etc/ssl/${DOMAIN}}

   API-Key (dem cert-distributor-Admin geben, damit er '$DOMAIN' damit registriert):
     $GENERATED_API_KEY

   nginx  : /etc/nginx/conf.d/${DOMAIN}.conf
            -> 'proxy_pass http://127.0.0.1:8080;' anpassen, dann 'nginx -t && systemctl reload nginx'
EOF
elif [[ -n $DOMAIN && -n $API_HOST ]]; then
  cat <<EOF

   Domain  : $DOMAIN
   api_url : https://${API_HOST}
   target  : ${TARGET_DIR_OPT:-/etc/ssl/${DOMAIN}}
EOF
else
  cat <<EOF

   Noch anzupassen ($CONFIG):
     Installer mit --domain und --api-host neu aufrufen, z. B.:
       \$0 --domain hermes.dyit.de --api-host certs.dyit.de
EOF
fi
