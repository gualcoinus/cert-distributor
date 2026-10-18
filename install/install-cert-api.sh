#!/usr/bin/env bash
# install-cert-api.sh – Installer für den cert-api-Server (gualcoinus/cert-distributor)
#
# Aufruf (typisch, kopieren & einfügen):
#   curl -fsSL https://raw.githubusercontent.com/gualcoinus/cert-distributor/main/install/install-cert-api.sh \
#     | sudo bash
#
# Optionale Argumente (nach `bash`, durch -- getrennt):
#   --version vX.Y.Z          statt neuestem Release
#   --repo    OWNER/REPO      Default: gualcoinus/cert-distributor
#   --bin-dir /usr/local/bin  Installationspfad der Binaries
#   --conf-dir /etc/cert-api  Konfigurationsverzeichnis
#   --live    /etc/letsencrypt/live   Basispfad
#   --archive /etc/letsencrypt/archive Basispfad
#   --no-systemd              nur Binaries + Config ablegen, keine Unit installieren
#   --no-nginx                nginx-Konfiguration nicht mitliefern
#   --uninstall               installierte Dateien wieder entfernen
#   -h | --help
set -Eeuo pipefail

REPO="gualcoinus/cert-distributor"
VERSION=""
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/cert-api"
LIVE_BASE="/etc/letsencrypt/live"
ARCHIVE_BASE="/etc/letsencrypt/archive"
DO_SYSTEMD=1
DO_NGINX=1
DO_UNINSTALL=0

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)   VERSION="$2"; shift 2 ;;
    --repo)      REPO="$2";   shift 2 ;;
    --bin-dir)   BIN_DIR="$2"; shift 2 ;;
    --conf-dir)  CONF_DIR="$2"; shift 2 ;;
    --live)      LIVE_BASE="$2"; shift 2 ;;
    --archive)   ARCHIVE_BASE="$2"; shift 2 ;;
    --no-systemd) DO_SYSTEMD=0; shift ;;
    --no-nginx)   DO_NGINX=0; shift ;;
    --uninstall)  DO_UNINSTALL=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; usage; exit 2 ;;
  esac
done

# --- Rechte anfordern ----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Dieses Skript braucht root-Rechte (z. B. über sudo erneut aufrufen)." >&2
  exit 1
fi

for bin in curl tar awk grep sha256sum openssl; do
  command -v "$bin" >/dev/null || { echo "'$bin' wird benötigt" >&2; exit 1; }
done

API_REPO="https://api.github.com/repos/${REPO}"

# --- Architektur erkennen ------------------------------------------------------
detect_arch() {
  case "$(uname -m)" in
    x86_64)  echo "linux-x86_64" ;;
    aarch64) echo "linux-arm64"   ;;
    armv7l)  echo "linux-armv7"   ;;
    *)
      echo "Nicht unterstützte Architektur: $(uname -m) (erwartet: x86_64, aarch64, armv7l)" >&2
      exit 1
      ;;
  esac
}

# --- Version bestimmen ---------------------------------------------------------
resolve_version() {
  if [[ -n $VERSION ]]; then
    echo "$VERSION"; return
  fi
  local tag
  tag="$(curl -fsSL "$API_REPO/releases/latest" | awk -F'"' '/"tag_name":/{print $4; exit}')"
  [[ -n $tag ]] || { echo "Konnte neuestes Release nicht ermitteln (Rate-Limit?). --version angeben." >&2; exit 1; }
  echo "$tag"
}

# --- Uninstall ----------------------------------------------------------------
if (( DO_UNINSTALL )); then
  if (( DO_SYSTEMD )) && command -v systemctl >/dev/null; then
    systemctl disable --now cert-api 2>/dev/null || true
    rm -f /etc/systemd/system/cert-api.service
    systemctl daemon-reload
  fi
  rm -f "$BIN_DIR/cert-api"
  rm -rf "$CONF_DIR"
  echo "cert-api deinstalliert (Benutzer/Gruppe bleiben bestehen – 'userdel cert-api' falls gewünscht)."
  exit 0
fi

ARCH="$(detect_arch)"
TAG="$(resolve_version)"
ASSET="cert-api-${TAG}-${ARCH}.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Lade $ASSET"
curl -fsSL -o "$TMP/$ASSET" "$API_REPO/releases/download/$TAG/$ASSET"
curl -fsSL -o "$TMP/$ASSET.sha256" "$API_REPO/releases/download/$TAG/$ASSET.sha256"
( cd "$TMP" && sha256sum -c "$ASSET.sha256" )

tar -xzf "$TMP/$ASSET" -C "$TMP"
PKG_DIR="$(find "$TMP" -maxdepth 1 -type d -name "cert-api-${TAG}-${ARCH}" | head -n1)"

# --- Binary installieren -------------------------------------------------------
install -m 0755 "$PKG_DIR/cert-api" "$BIN_DIR/cert-api"

# --- Benutzer / Gruppe anlegen (idempotent) ------------------------------------
CERT_USER="cert-api"
CERT_GROUP="cert-api"
SSL_GROUP="ssl-cert"

getent group  "$SSL_GROUP" >/dev/null || groupadd --system "$SSL_GROUP"
getent group  "$CERT_GROUP" >/dev/null || groupadd --system "$CERT_GROUP"
getent passwd "$CERT_USER"  >/dev/null || \
  useradd  --system --gid "$CERT_GROUP" --home "$CONF_DIR" --shell /usr/sbin/nologin \
           --comment "cert-api service account" "$CERT_USER"
# cert-api in ssl-cert aufnehmen, damit es live/archive lesen darf
usermod -aG "$SSL_GROUP" "$CERT_USER"

# --- Let's-Encrypt-Pfade finden -----------------------------------------------
echo
echo "==> Suche Let's-Encrypt-Zertifikate"
if [[ -d $LIVE_BASE ]]; then
  echo "    live   = $LIVE_BASE"
else
  echo "    live   = $LIVE_BASE  (FEHLT – certbot installieren oder --live anpassen)" >&2
fi
if [[ -d $ARCHIVE_BASE ]]; then
  echo "    archive= $ARCHIVE_BASE"
else
  echo "    archive= $ARCHIVE_BASE  (optional – fehlt, --archive anpassen oder weglassen)" >&2
fi

# --- Rechte an /etc/letsencrypt -----------------------------------------------
# lebende Schlüssel bleiben world-readable wie von certbot vorgesehen;
# nur die Gruppe ssl-cert bekommt zusätzlichen Lesezugriff für den Dienst.
chgrp -R "$SSL_GROUP" "$LIVE_BASE"  2>/dev/null || true
chmod -R g+rX                    "$LIVE_BASE"  2>/dev/null || true
[[ -d $ARCHIVE_BASE ]] && {
  chgrp -R "$SSL_GROUP" "$ARCHIVE_BASE" 2>/dev/null || true
  chmod -R g+rX                      "$ARCHIVE_BASE" 2>/dev/null || true
}
# privkey.pem ist mode 600 in neueren certbot-Versionen → Gruppe lesend machen
find "$LIVE_BASE" "$ARCHIVE_BASE" -type f -name 'privkey*.pem' 2>/dev/null \
  -exec chgrp "$SSL_GROUP" {} \; -exec chmod g+r {} \;

# --- Konfigurationsverzeichnis -----------------------------------------------
install -d -m 0750 -o root -g "$CERT_GROUP" "$CONF_DIR"

CONFIG="$CONF_DIR/config.toml"
if [[ ! -f $CONFIG ]]; then
  ( umask 077
    cat >"$CONFIG" <<EOF
# Muss eine Loopback-Adresse sein, nginx macht TLS davor.
listen = "127.0.0.1:8443"

# Beispiel-Eintrag – mit scripts/add-cert.sh (aus dem Release) ergänzen.
# openssl rand -hex 32
EOF
  )
  echo "Leere Konfiguration angelegt: $CONFIG"
fi

# --- systemd ------------------------------------------------------------------
if (( DO_SYSTEMD )) && command -v systemctl >/dev/null; then
  install -m 0644 "$PKG_DIR/deploy/cert-api.service" /etc/systemd/system/cert-api.service
  # systemd-Drop-in für konfigurierbare Pfade
  install -d -m 0755 /etc/systemd/system/cert-api.service.d
  cat >/etc/systemd/system/cert-api.service.d/override.conf <<EOF
[Service]
Environment=CERT_API_LIVE_BASE=$LIVE_BASE
Environment=CERT_API_ARCHIVE_BASE=$ARCHIVE_BASE
EOF
  systemctl daemon-reload
  systemctl enable --now cert-api
  echo "systemd-Dienst 'cert-api' gestartet."
  systemctl --no-pager status cert-api || true
else
  echo "systemd nicht installiert/gewünscht – manuell starten: $BIN_DIR/cert-api $CONFIG"
fi

# --- nginx-Snippet ablegen ---------------------------------------------------
if (( DO_NGINX )); then
  install -d -m 0755 /etc/cert-api/nginx
  if [[ -f $PKG_DIR/cert-api/nginx.conf.example ]]; then
    install -m 0644 "$PKG_DIR/cert-api/nginx.conf.example" /etc/cert-api/nginx/cert-api.conf
    echo "nginx-Vorlage: /etc/cert-api/nginx/cert-api.conf (in eigenen server-Block übernehmen)"
  fi
fi

# add-cert.sh für die Folge-Inserts an die übliche Stelle legen
if [[ -f $PKG_DIR/scripts/add-cert.sh ]]; then
  install -d -m 0755 /usr/local/share/cert-api
  install -m 0755 "$PKG_DIR/scripts/add-cert.sh" /usr/local/share/cert-api/add-cert.sh
fi

cat <<EOF

==> Fertig.
   Binary : $BIN_DIR/cert-api
   Config : $CONFIG
   User   : $CERT_USER  Group(s): $CERT_GROUP,$SSL_GROUP
   LE     : $LIVE_BASE   ($ARCHIVE_BASE)

   Neues Zertifikat eintragen:
     /usr/local/share/cert-api/add-cert.sh -c $CONFIG example.com
     # oder (immer aktuell):
     curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/add-cert.sh \
       | sudo bash -s -- -c $CONFIG example.com

EOF
