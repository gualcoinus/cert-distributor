#!/usr/bin/env bash
# install-cert-sync.sh – Installer für den cert-sync-Client (gualcoinus/cert-distributor)
#
# Aufruf (typisch, kopieren & einfügen):
#   curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-sync.sh \
#     | sudo bash
#
# Optionale Argumente (nach `bash`, durch -- getrennt):
#   --version   vX.Y.Z          statt neuestem Release
#   --repo      OWNER/REPO      Default: gualcoinus/cert-distributor
#   --bin-dir   /usr/local/bin
#   --conf-dir  /etc/cert-sync
#   --bin-name  cert-sync       Alternativer Binary-Name (z. B. cert-sync-bash)
#   --api-url   https://cert...  trägt api_url direkt in cert-sync.toml ein
#   --cert      name:key:target[:reload_cmd]  wiederholbar, eine [[certificates]]-Sektion je Eintrag
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
API_URL_OPT=""
CERT_ENTRIES=()                       # "name|key|target|reload"
DO_CRON=1
CRON_TIME="17 3 * * *"
DO_DRYRUN=0
DO_UNINSTALL=0

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="$2"; shift 2 ;;
    --repo)       REPO="$2";    shift 2 ;;
    --bin-dir)    BIN_DIR="$2"; shift 2 ;;
    --conf-dir)   CONF_DIR="$2"; shift 2 ;;
    --bin-name)   BIN_NAME="$2"; shift 2 ;;
    --api-url)    API_URL_OPT="$2"; shift 2 ;;
    --cert)       CERT_ENTRIES+=("$2"); shift 2 ;;
    --no-cron)    DO_CRON=0; shift ;;
    --cron-time)  CRON_TIME="$2"; shift 2 ;;
    --dry-run)    DO_DRYRUN=1; shift ;;
    --uninstall)  DO_UNINSTALL=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Dieses Skript braucht root-Rechte (sudo)." >&2; exit 1
fi
for bin in curl tar awk grep sha256sum; do
  command -v "$bin" >/dev/null || { echo "'$bin' wird benötigt" >&2; exit 1; }
done

API_REPO="https://api.github.com/repos/${REPO}"

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
  echo "cert-sync deinstalliert (Log unter /var/log/cert-sync.log bleibt bestehen)."
  exit 0
fi

ARCH="$(detect_arch)"
TAG="$(resolve_version)"
ASSET="cert-sync-${TAG}-${ARCH}.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Lade $ASSET"
curl -fsSL -o "$TMP/$ASSET"             "$API_REPO/releases/download/$TAG/$ASSET"
curl -fsSL -o "$TMP/$ASSET.sha256"      "$API_REPO/releases/download/$TAG/$ASSET.sha256"
( cd "$TMP" && sha256sum -c "$ASSET.sha256" )

tar -xzf "$TMP/$ASSET" -C "$TMP"
PKG_DIR="$(find "$TMP" -maxdepth 1 -type d -name "cert-sync-${TAG}-${ARCH}" | head -n1)"

install -m 0755 "$PKG_DIR/cert-sync" "$BIN_DIR/$BIN_NAME"
# alternativer Bash-Client aus dem selben Paket
[[ -f $PKG_DIR/scripts/cert-sync.sh ]] && install -m 0755 "$PKG_DIR/scripts/cert-sync.sh" "$BIN_DIR/cert-sync.sh" || true
# Cron-Beispiel aus dem Paket daneben ablegen
# Cron-Beispiele aus dem Paket ablegen. Im neuen Split-Tarball liegen beide
# Varianten unter unterschiedlichen Namen: cert-sync.cron.example (Rust)
# und cert-sync.sh.cron.example (Bash-Alternative).
if [[ -f $PKG_DIR/cert-sync.cron.example ]]; then
  install -m 0644 "$PKG_DIR/cert-sync.cron.example" /etc/cert-sync/cert-sync.cron.example
elif [[ -f $PKG_DIR/scripts/cert-sync.cron.example ]]; then
  install -m 0644 "$PKG_DIR/scripts/cert-sync.cron.example" /etc/cert-sync/cert-sync.cron.example
fi
if [[ -f $PKG_DIR/cert-sync.sh.cron.example ]]; then
  install -m 0644 "$PKG_DIR/cert-sync.sh.cron.example" /etc/cert-sync/cert-sync.sh.cron.example
fi

# Config-Verzeichnis mit restriktiven Rechten
install -d -m 0700 -o root -g root "$CONF_DIR"

CONFIG="$CONF_DIR/cert-sync.toml"
write_config() {
  ( umask 077
    {
      printf '# cert-sync-Konfiguration – generiert von install-cert-sync.sh\n'
      printf 'api_url    = "%s"\n' "$1"
      printf 'reload_cmd = "nginx -t && systemctl reload nginx"\n'
      printf '\n'
      local entry name key target reload
      for entry in "${CERT_ENTRIES[@]:-}"; do
        [[ -z $entry ]] && continue
        IFS='|' read -r name key target reload <<<"$entry"
        if [[ -z $name || -z $key || -z $target ]]; then
          echo "Ungültiges --cert-Argument: '$entry' (erwartet: name|key|target_dir optional mit |reload_cmd)" >&2
          return 1
        fi
        printf '[[certificates]]\n'
        printf 'name       = "%s"\n' "$name"
        printf 'api_key    = "%s"\n' "$key"
        printf 'target_dir = "%s"\n' "$target"
        [[ -n $reload ]] && printf 'reload_cmd = "%s"\n' "$reload"
        printf '\n'
      done
    } > "$CONFIG"
  )
  chmod 600 "$CONFIG"
}

if [[ ! -f $CONFIG ]]; then
  if [[ -n $API_URL_OPT || ${#CERT_ENTRIES[@]} -gt 0 ]]; then
    # Mindestens --api-url oder --cert angegeben → eigene Config generieren
    [[ $API_URL_OPT =~ ^https?:// ]] \
      || { echo "--api-url muss mit http:// oder https:// beginnen: $API_URL_OPT" >&2; exit 2; }
    API_URL_OPT="${API_URL_OPT%/}"
    write_config "$API_URL_OPT"
    echo "Konfiguration generiert: $CONFIG"
  else
    # Fallback: unverändertes Beispiel aus dem Release-Tarball, Nutzer trägt selbst nach.
    if [[ -f $PKG_DIR/cert-sync/cert-sync.example.toml ]]; then
      install -m 0600 "$PKG_DIR/cert-sync/cert-sync.example.toml" "$CONFIG"
    else
      curl -fsSL -o "$CONFIG" \
        "https://raw.githubusercontent.com/${REPO}/main/cert-sync/cert-sync.example.toml"
      chmod 600 "$CONFIG"
    fi
    echo "Beispiel-Config abgelegt: $CONFIG  (jetzt api_url und jeden Block anpassen)"
  fi
elif [[ -n $API_URL_OPT || ${#CERT_ENTRIES[@]} -gt 0 ]]; then
  echo "Hinweis: $CONFIG existiert bereits – --api-url/--cert werden ignoriert." >&2
  echo "         'sudo $BIN_NAME --check-only' nutzt die vorhandene Datei." >&2
fi

if (( DO_CRON )) && command -v systemctl >/dev/null && [[ -d /etc/cron.d ]]; then
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

if [[ -n $API_URL_OPT || ${#CERT_ENTRIES[@]} -gt 0 ]]; then
  cat <<EOF

   api_url   : $API_URL_OPT
   certs     : ${#CERT_ENTRIES[@]} Eintrag/Einträge hinterlegt

   Weitere Zertifikate nachträglich eintragen:
     \$EDITOR $CONFIG     # einfach [[certificates]]-Block anhängen
EOF
else
  cat <<EOF

   Noch anzupassen ($CONFIG):
     api_url = "https://certs.example.com"
     [[certificates]] name / api_key / target_dir / ggf. reload_cmd
     $BIN_NAME --check-only -c $CONFIG
EOF
fi
