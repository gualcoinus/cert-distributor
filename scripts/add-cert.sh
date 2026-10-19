#!/usr/bin/env bash
# add-cert.sh – fügt der cert-api-Konfiguration ein neues Zertifikat (inkl. neuem API-Key) hinzu.
set -euo pipefail

usage() {
  cat <<USAGE
Verwendung: $(basename "$0") [Optionen] <domain>

Hängt einen [[certificates]]-Block mit frisch erzeugtem API-Key an die Konfiguration an.

Optionen:
  -c <datei>   Konfigurationsdatei (Default: \$CERT_API_CONFIG oder ./config.toml)
  -l <pfad>    Basispfad der live-Verzeichnisse    (Default: /etc/letsencrypt/live)
  -a <pfad>    Basispfad der archive-Verzeichnisse (Default: /etc/letsencrypt/archive)
  -n           Keinen archive_path eintragen
  -r <dienst>  systemd-Dienst danach neu starten (z. B. cert-api)
  -h           Diese Hilfe
USAGE
}

CONFIG="${CERT_API_CONFIG:-./config.toml}"
LIVE_BASE="/etc/letsencrypt/live"
ARCHIVE_BASE="/etc/letsencrypt/archive"
USE_ARCHIVE=1
SERVICE=""

while getopts ":c:l:a:n:r:h" opt; do
  case "$opt" in
    c) CONFIG=$OPTARG ;;
    l) LIVE_BASE=$OPTARG ;;
    a) ARCHIVE_BASE=$OPTARG ;;
    n) USE_ARCHIVE=0 ;;
    r) SERVICE=$OPTARG ;;
    h) usage; exit 0 ;;
    \?) echo "Unbekannte Option: -$OPTARG" >&2; usage >&2; exit 2 ;;
    :)  echo "Option -$OPTARG braucht ein Argument" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
DOMAIN="${1,,}"

# Gleiche Regeln wie die API: a-z 0-9 . - _ (Wildcard-Zertifikate liegen bei certbot unter dem Basisnamen)
re='^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'
if [[ ! $DOMAIN =~ $re || $DOMAIN == *..* ]]; then
  echo "Ungültiger Domain-Name: '$DOMAIN'" >&2
  exit 2
fi

command -v openssl >/dev/null || { echo "openssl wird benötigt" >&2; exit 1; }

# Konfiguration anlegen, falls sie noch nicht existiert
if [[ ! -f $CONFIG ]]; then
  (umask 077
   printf '# Muss eine Loopback-Adresse sein, nginx macht TLS davor.\nlisten = "127.0.0.1:8443"\n' > "$CONFIG")
  echo "Neue Konfiguration angelegt: $CONFIG (Rechte 600)"
fi

# Doppelte Einträge verhindern
esc="${DOMAIN//./\\.}"
if grep -Eq "^[[:space:]]*name[[:space:]]*=[[:space:]]*\"$esc\"" "$CONFIG"; then
  echo "Fehler: '$DOMAIN' ist in $CONFIG bereits eingetragen." >&2
  exit 1
fi

if [[ ! -d "${LIVE_BASE%/}/$DOMAIN" ]]; then
  echo "Hinweis: ${LIVE_BASE%/}/$DOMAIN existiert (noch) nicht." >&2
fi

KEY="$(openssl rand -hex 32)"   # 64 Zeichen

BACKUP="$CONFIG.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$CONFIG" "$BACKUP"

{
  printf '\n[[certificates]]\n'
  printf 'name = "%s"\n' "$DOMAIN"
  printf 'api_key = "%s"\n' "$KEY"
  printf 'live_path = "%s/%s"\n' "${LIVE_BASE%/}" "$DOMAIN"
  if (( USE_ARCHIVE )); then
    printf 'archive_path = "%s/%s"\n' "${ARCHIVE_BASE%/}" "$DOMAIN"
  fi
} >> "$CONFIG"

echo "Eingetragen in $CONFIG (Backup: $BACKUP)"
echo
echo "  Name:     $DOMAIN"
echo "  API-Key:  $KEY"
echo
echo "Den Key jetzt in die Client-Konfiguration (cert-sync.conf) übernehmen."

if [[ -n $SERVICE ]]; then
  systemctl restart "$SERVICE"
  echo "Dienst '$SERVICE' neu gestartet."
else
  echo "Achtung: Die API liest die Konfiguration nur beim Start – Dienst neu starten (z. B. systemctl restart cert-api)."
fi
