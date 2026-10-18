#!/usr/bin/env bash
# cert-sync.sh – Gegenstück zur cert-api: prüft täglich (Cron) auf ein neues Zertifikat,
# lädt es herunter, validiert es, tauscht es atomar aus und lädt den Dienst neu.
#
# Aufruf:  cert-sync.sh [/pfad/zur/cert-sync.conf]
set -Eeuo pipefail
umask 077

CONF="${1:-/etc/cert-sync/cert-sync.conf}"
[[ -r $CONF ]] || { echo "Konfiguration '$CONF' nicht lesbar" >&2; exit 2; }
# shellcheck disable=SC1090
source "$CONF"

: "${API_URL:?API_URL fehlt}" "${CERT_NAME:?CERT_NAME fehlt}" "${API_KEY:?API_KEY fehlt}" "${TARGET_DIR:?TARGET_DIR fehlt}"
API_URL="${API_URL%/}"
RELOAD_CMD="${RELOAD_CMD:-}"
KEEP_BACKUPS="${KEEP_BACKUPS:-5}"
FILE_GROUP="${FILE_GROUP:-}"            # optional: Gruppe, die privkey.pem lesen darf
SPLAY="${SPLAY:-0}"                     # optional: zufällige Verzögerung in Sekunden
WARN_DAYS="${WARN_DAYS:-14}"
LOCK_DIR="${LOCK_DIR:-/var/lock}"
PROTO='=https'
[[ ${ALLOW_INSECURE_HTTP:-0} == 1 ]] && PROTO='=http,https'

log()  { printf '%s cert-sync[%s]: %s\n' "$(date '+%F %T')" "$CERT_NAME" "$*"; }
warn() { log "WARNUNG: $*" >&2; }
trap 'log "FEHLER (Zeile $LINENO)" >&2' ERR

for bin in curl openssl flock; do
  command -v "$bin" >/dev/null || { echo "'$bin' wird benötigt" >&2; exit 2; }
done

# Die Config enthält den API-Key
perm="$(stat -c %a "$CONF")"
[[ ${perm: -2} == 00 ]] || warn "$CONF ist für Gruppe/Andere lesbar (empfohlen: chmod 600)"

# Nur eine Instanz pro Zertifikat gleichzeitig
exec 9>"$LOCK_DIR/cert-sync-$CERT_NAME.lock"
flock -n 9 || { log "läuft bereits – Abbruch"; exit 0; }

if (( SPLAY > 0 )); then sleep $(( RANDOM % SPLAY )); fi

# API-Aufruf; der Key wird über stdin übergeben (nicht in der Prozessliste sichtbar)
api() {   # $1 = Pfad (+Query), $2 = optionale Ausgabedatei
  local args=(-fsS --proto "$PROTO" --max-time 30 --retry 3 --retry-delay 5)
  [[ -n ${2:-} ]] && args+=(-o "$2")
  printf 'header = "X-API-Key: %s"\n' "$API_KEY" | curl -K - "${args[@]}" "$API_URL$1"
}

fp_of() {  # SHA-256-Fingerprint (hex, klein) des ersten Zertifikats einer PEM-Datei
  openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
}

mkdir -p "$TARGET_DIR"
CUR_CERT="$TARGET_DIR/fullchain.pem"
CUR_KEY="$TARGET_DIR/privkey.pem"

local_fp=""
if [[ -f $CUR_CERT ]]; then
  local_fp="$(fp_of "$CUR_CERT" 2>/dev/null || true)"
fi

# --- 1. Gibt es ein neues Zertifikat? -------------------------------------------------
if [[ -z $local_fp ]]; then
  log "Kein lokales Zertifikat vorhanden – Erstabruf"
else
  resp="$(api "/v1/certs/$CERT_NAME/check?fingerprint=$local_fp")"
  if grep -q '"update_available":false' <<<"$resp"; then
    log "Zertifikat aktuell (${local_fp:0:16}…)"
    if ! openssl x509 -in "$CUR_CERT" -noout -checkend $(( WARN_DAYS * 86400 )) >/dev/null; then
      warn "Lokales Zertifikat läuft in weniger als $WARN_DAYS Tagen ab, API liefert aber kein neues!"
    fi
    exit 0
  elif ! grep -q '"update_available":true' <<<"$resp"; then
    echo "Unerwartete Antwort der API: $resp" >&2
    exit 1
  fi
  log "Neues Zertifikat verfügbar"
fi

# --- 2. Herunterladen & validieren ----------------------------------------------------
tmp="$(mktemp -d "$TARGET_DIR/.sync.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

api "/v1/certs/$CERT_NAME/files/fullchain.pem" "$tmp/fullchain.pem"
api "/v1/certs/$CERT_NAME/files/privkey.pem"   "$tmp/privkey.pem"

openssl x509 -in "$tmp/fullchain.pem" -noout \
  || { echo "Heruntergeladenes Zertifikat ist ungültig" >&2; exit 1; }
openssl x509 -in "$tmp/fullchain.pem" -noout -checkend 0 >/dev/null \
  || { echo "Heruntergeladenes Zertifikat ist bereits abgelaufen" >&2; exit 1; }

cert_pub="$(openssl x509 -in "$tmp/fullchain.pem" -noout -pubkey)"
key_pub="$(openssl pkey -in "$tmp/privkey.pem" -pubout)"
[[ $cert_pub == "$key_pub" ]] \
  || { echo "Privater Schlüssel passt nicht zum Zertifikat" >&2; exit 1; }

new_fp="$(fp_of "$tmp/fullchain.pem")"
if [[ $new_fp == "$local_fp" ]]; then
  log "Fingerprint unverändert – nichts zu tun"
  exit 0
fi

# --- 3. Backup & Austausch -------------------------------------------------------------
had_old=0
backup="$TARGET_DIR/backup/$(date +%Y%m%d-%H%M%S)"
if [[ -f $CUR_CERT && -f $CUR_KEY ]]; then
  mkdir -p "$backup"
  cp -p "$CUR_CERT" "$CUR_KEY" "$backup/"
  had_old=1
fi

chmod 644 "$tmp/fullchain.pem"
chmod 600 "$tmp/privkey.pem"
if [[ -n $FILE_GROUP ]]; then
  chgrp "$FILE_GROUP" "$tmp/privkey.pem"
  chmod 640 "$tmp/privkey.pem"
fi
mv -f "$tmp/privkey.pem"   "$CUR_KEY"
mv -f "$tmp/fullchain.pem" "$CUR_CERT"
log "Neues Zertifikat installiert (${new_fp:0:16}…), gültig bis $(openssl x509 -in "$CUR_CERT" -noout -enddate | cut -d= -f2)"

# --- 4. Dienst neu laden (bei Fehler Rollback) -------------------------------------------
if [[ -n $RELOAD_CMD ]]; then
  if ! bash -c "$RELOAD_CMD"; then
    echo "Reload fehlgeschlagen: $RELOAD_CMD" >&2
    if (( had_old )); then
      cp -p "$backup/fullchain.pem" "$CUR_CERT"
      cp -p "$backup/privkey.pem"   "$CUR_KEY"
      bash -c "$RELOAD_CMD" || true
      warn "Altes Zertifikat wiederhergestellt"
    fi
    exit 1
  fi
  log "Reload ausgeführt: $RELOAD_CMD"
fi

# Alte Backups aufräumen
if [[ -d $TARGET_DIR/backup ]]; then
  find "$TARGET_DIR/backup" -mindepth 1 -maxdepth 1 -type d | sort -r \
    | tail -n +"$((KEEP_BACKUPS + 1))" | xargs -r rm -rf
fi
log "Fertig"
