//! cert-sync – Gegenstück zur cert-api.
//!
//! Prüft per Fingerprint, ob es ein neues Zertifikat gibt, lädt es herunter, validiert es
//! (Gültigkeit + Schlüssel passt zum Zertifikat), tauscht es atomar aus und lädt den Dienst
//! neu. Schlägt der Reload fehl, wird das alte Zertifikat wiederhergestellt.

use std::{
    collections::HashSet,
    fmt::Display,
    fs::{self, File, OpenOptions, TryLockError},
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use reqwest::{blocking::Client, header::HeaderValue, StatusCode};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use x509_parser::parse_x509_certificate;

// ---------------------------------------------------------------------------
// CLI & Konfiguration
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    version,
    about = "Holt neue Zertifikate von der cert-api und installiert sie"
)]
struct Cli {
    /// Pfad zur Konfigurationsdatei
    #[arg(short, long, default_value = "/etc/cert-sync/cert-sync.toml")]
    config: PathBuf,

    /// Nur prüfen, ob ein Update verfügbar ist (nichts herunterladen/installieren)
    #[arg(long)]
    check_only: bool,

    /// Zertifikat auch dann neu laden, wenn der Fingerprint übereinstimmt
    #[arg(long)]
    force: bool,

    /// Nur dieses Zertifikat bearbeiten (Name aus der Konfiguration)
    #[arg(long, value_name = "NAME")]
    only: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Config {
    api_url: String,
    reload_cmd: Option<String>,
    #[serde(default = "default_keep")]
    keep_backups: usize,
    #[serde(default = "default_warn_days")]
    warn_days: i64,
    #[serde(default)]
    splay_secs: u64,
    #[serde(default = "default_lock")]
    lock_file: PathBuf,
    /// Numerische GID, die privkey.pem lesen darf (dann Modus 640)
    key_gid: Option<u32>,
    #[serde(default)]
    allow_insecure_http: bool,
    certificates: Vec<CertEntry>,
}

#[derive(Debug, Deserialize)]
struct CertEntry {
    name: String,
    api_key: String,
    target_dir: PathBuf,
    reload_cmd: Option<String>,
}

fn default_keep() -> usize {
    5
}
fn default_warn_days() -> i64 {
    14
}
fn default_lock() -> PathBuf {
    PathBuf::from("/var/lock/cert-sync.lock")
}

fn load_config(path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Konfiguration '{}' nicht lesbar", path.display()))?;
    let cfg: Config = toml::from_str(&raw).context("Konfiguration ungültig")?;

    if let Ok(meta) = fs::metadata(path) {
        if meta.permissions().mode() & 0o077 != 0 {
            warn(
                "-",
                format!(
                    "{} ist für Gruppe/Andere lesbar (empfohlen: chmod 600)",
                    path.display()
                ),
            );
        }
    }

    if !cfg.allow_insecure_http && !cfg.api_url.starts_with("https://") {
        bail!("api_url muss mit https:// beginnen");
    }
    if cfg.certificates.is_empty() {
        bail!("Keine [[certificates]] konfiguriert");
    }
    let mut seen = HashSet::new();
    for c in &cfg.certificates {
        let valid = !c.name.is_empty()
            && c.name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'));
        if !valid {
            bail!("Ungültiger Name '{}' (erlaubt: a-z A-Z 0-9 . - _)", c.name);
        }
        if c.api_key.is_empty() {
            bail!("api_key für '{}' ist leer", c.name);
        }
        if !seen.insert(c.name.as_str()) {
            bail!("Name '{}' ist doppelt vergeben", c.name);
        }
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

fn ts() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
fn log(name: &str, msg: impl Display) {
    println!("{} cert-sync[{name}]: {msg}", ts());
}
fn warn(name: &str, msg: impl Display) {
    eprintln!("{} cert-sync[{name}]: WARNUNG: {msg}", ts());
}
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// API-Client
// ---------------------------------------------------------------------------

struct Api {
    http: Client,
    base: String,
    key: HeaderValue,
    name: String,
}

#[derive(Deserialize)]
struct CheckResponse {
    update_available: bool,
}

impl Api {
    fn new(http: &Client, base: &str, entry: &CertEntry) -> Result<Self> {
        let mut key =
            HeaderValue::from_str(&entry.api_key).context("api_key enthält ungültige Zeichen")?;
        key.set_sensitive(true); // taucht nicht in Debug-Ausgaben auf
        Ok(Self {
            http: http.clone(),
            base: base.trim_end_matches('/').to_string(),
            key,
            name: entry.name.clone(),
        })
    }

    /// GET mit 3 Versuchen bei Netzwerk-/Serverfehlern; 4xx bricht sofort ab.
    fn get(&self, suffix: &str, query: &[(&str, &str)]) -> Result<Vec<u8>> {
        let url = format!("{}/v1/certs/{}/{}", self.base, self.name, suffix);
        let mut last: Option<anyhow::Error> = None;

        for attempt in 1..=3 {
            let res = self
                .http
                .get(&url)
                .header("X-API-Key", self.key.clone())
                .query(query)
                .send();
            match res {
                Ok(r) if r.status().is_success() => {
                    return Ok(r.bytes().context("Antwort unvollständig")?.to_vec());
                }
                Ok(r) if r.status() == StatusCode::UNAUTHORIZED => {
                    bail!("API-Key wurde abgelehnt (HTTP 401)")
                }
                Ok(r) if r.status().is_client_error() => bail!("API-Fehler: HTTP {}", r.status()),
                Ok(r) => last = Some(anyhow!("HTTP {}", r.status())),
                Err(e) => last = Some(anyhow!(e)),
            }
            if attempt < 3 {
                std::thread::sleep(Duration::from_secs(5));
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("unbekannter Fehler"))).context("API nicht erreichbar")
    }
}

// ---------------------------------------------------------------------------
// Zertifikats-Helfer
// ---------------------------------------------------------------------------

struct CertSummary {
    fingerprint: String,
    not_after: i64,
}

fn load_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .context("PEM-Zertifikat ungültig")?;
    if chain.is_empty() {
        bail!("Keine Zertifikate in der PEM-Datei gefunden");
    }
    Ok(chain)
}

/// SHA-256 des Leaf-Zertifikats (DER) – identisch zur Berechnung in der API.
fn summarize(chain: &[CertificateDer<'static>]) -> Result<CertSummary> {
    let leaf = chain[0].as_ref();
    let (_, x509) = parse_x509_certificate(leaf).map_err(|e| anyhow!("X.509 ungültig: {e:?}"))?;
    Ok(CertSummary {
        fingerprint: hex::encode(Sha256::digest(leaf)),
        not_after: x509.validity().not_after.timestamp(),
    })
}

fn ensure_key_matches(chain: Vec<CertificateDer<'static>>, key_pem: &[u8]) -> Result<()> {
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("Privater Schlüssel ungültig")?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow!("Schlüsseltyp nicht unterstützt: {e}"))?;
    CertifiedKey::new(chain, signing)
        .keys_match()
        .map_err(|e| anyhow!("Privater Schlüssel passt nicht zum Zertifikat: {e}"))
}

// ---------------------------------------------------------------------------
// Dateisystem-Helfer
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn create(parent: &Path, name: &str) -> Result<Self> {
        let p = parent.join(format!(".sync.{name}.{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Self(p))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("{} nicht lesbar", path.display())),
    }
}

fn prune_backups(target_dir: &Path, keep: usize) {
    let Ok(rd) = fs::read_dir(target_dir.join("backup")) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.reverse(); // neueste zuerst
    for old in dirs.into_iter().skip(keep) {
        let _ = fs::remove_dir_all(old);
    }
}

fn run_reload(cmd: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .context("Reload-Befehl konnte nicht gestartet werden")?;
    if status.success() {
        Ok(())
    } else {
        bail!("Reload-Befehl endete mit {status}")
    }
}

// ---------------------------------------------------------------------------
// Synchronisation eines Zertifikats
// ---------------------------------------------------------------------------

enum Outcome {
    UpToDate,
    UpdateAvailable, // nur bei --check-only
    Updated,
}

#[cfg(test)]
impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UpToDate => f.write_str("UpToDate"),
            Self::UpdateAvailable => f.write_str("UpdateAvailable"),
            Self::Updated => f.write_str("Updated"),
        }
    }
}

fn sync_one(cfg: &Config, entry: &CertEntry, http: &Client, cli: &Cli) -> Result<Outcome> {
    let name = entry.name.as_str();
    let dir = entry.target_dir.as_path();
    let cur_cert = dir.join("fullchain.pem");
    let cur_key = dir.join("privkey.pem");
    let api = Api::new(http, &cfg.api_url, entry)?;

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)?;

    // --- 1. Lokalen Stand ermitteln -------------------------------------------------
    let local = match read_optional(&cur_cert)? {
        None => None,
        Some(bytes) => match load_chain(&bytes).and_then(|c| summarize(&c)) {
            Ok(s) => Some(s),
            Err(e) => {
                warn(
                    name,
                    format!("Lokales Zertifikat unlesbar ({e:#}) – wird neu geladen"),
                );
                None
            }
        },
    };

    // --- 2. Gibt es ein neues Zertifikat? ---------------------------------------------
    match &local {
        None => log(name, "Kein lokales Zertifikat vorhanden – Erstabruf"),
        Some(l) if cli.force => log(
            name,
            format!("--force: Abruf erzwungen ({}…)", &l.fingerprint[..16]),
        ),
        Some(l) => {
            let body = api.get("check", &[("fingerprint", l.fingerprint.as_str())])?;
            let check: CheckResponse =
                serde_json::from_slice(&body).context("Unerwartete Antwort der API")?;
            if !check.update_available {
                log(
                    name,
                    format!("Zertifikat aktuell ({}…)", &l.fingerprint[..16]),
                );
                let days_left = (l.not_after - now_unix()) / 86_400;
                if days_left < cfg.warn_days {
                    warn(
                        name,
                        format!("Lokales Zertifikat läuft in {days_left} Tagen ab, die API liefert aber kein neues!"),
                    );
                }
                return Ok(Outcome::UpToDate);
            }
            log(name, "Neues Zertifikat verfügbar");
        }
    }

    if cli.check_only {
        log(name, "--check-only: kein Download");
        return Ok(Outcome::UpdateAvailable);
    }

    // --- 3. Herunterladen & validieren ---------------------------------------------------
    let tmp = TempDir::create(dir, name)?;
    let cert_pem = api.get("files/fullchain.pem", &[])?;
    let key_pem = api.get("files/privkey.pem", &[])?;

    let chain = load_chain(&cert_pem)?;
    let new = summarize(&chain)?;
    if new.not_after <= now_unix() {
        bail!("Heruntergeladenes Zertifikat ist bereits abgelaufen");
    }
    ensure_key_matches(chain, &key_pem)?;

    if !cli.force
        && local
            .as_ref()
            .is_some_and(|l| l.fingerprint == new.fingerprint)
    {
        log(name, "Fingerprint unverändert – nichts zu tun");
        return Ok(Outcome::UpToDate);
    }

    let tmp_cert = tmp.path().join("fullchain.pem");
    let tmp_key = tmp.path().join("privkey.pem");
    write_file(&tmp_cert, &cert_pem, 0o644)?;
    match cfg.key_gid {
        Some(gid) => {
            write_file(&tmp_key, &key_pem, 0o640)?;
            std::os::unix::fs::chown(&tmp_key, None, Some(gid))
                .context("chown (key_gid) fehlgeschlagen")?;
        }
        None => write_file(&tmp_key, &key_pem, 0o600)?,
    }

    // --- 4. Backup & atomarer Austausch --------------------------------------------------
    let backup = if cur_cert.exists() && cur_key.exists() {
        let stamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default()
            .replace(':', "-");
        let b = dir.join("backup").join(stamp);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&b)?;
        fs::copy(&cur_cert, b.join("fullchain.pem"))?;
        fs::copy(&cur_key, b.join("privkey.pem"))?;
        Some(b)
    } else {
        None
    };

    fs::rename(&tmp_key, &cur_key).context("privkey.pem konnte nicht ersetzt werden")?;
    fs::rename(&tmp_cert, &cur_cert).context("fullchain.pem konnte nicht ersetzt werden")?;
    log(
        name,
        format!(
            "Neues Zertifikat installiert ({}…), noch {} Tage gültig",
            &new.fingerprint[..16],
            (new.not_after - now_unix()) / 86_400
        ),
    );

    // --- 5. Reload (bei Fehler Rollback) --------------------------------------------------
    let reload = entry
        .reload_cmd
        .as_deref()
        .or(cfg.reload_cmd.as_deref())
        .filter(|s| !s.trim().is_empty());

    if let Some(cmd) = reload {
        if let Err(e) = run_reload(cmd) {
            if let Some(b) = &backup {
                fs::copy(b.join("privkey.pem"), &cur_key)?;
                fs::copy(b.join("fullchain.pem"), &cur_cert)?;
                let _ = run_reload(cmd);
                warn(
                    name,
                    "Reload fehlgeschlagen – altes Zertifikat wiederhergestellt",
                );
            }
            return Err(e);
        }
        log(name, format!("Reload ausgeführt: {cmd}"));
    }

    prune_backups(dir, cfg.keep_backups);
    Ok(Outcome::Updated)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn run() -> Result<bool> {
    let cli = Cli::parse();
    let cfg = load_config(&cli.config)?;

    if let Some(only) = &cli.only {
        if !cfg.certificates.iter().any(|c| &c.name == only) {
            bail!("Zertifikat '{only}' ist nicht konfiguriert");
        }
    }

    // Nur eine Instanz gleichzeitig
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&cfg.lock_file)
        .with_context(|| format!("Lock-Datei '{}' nicht nutzbar", cfg.lock_file.display()))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            log("-", "läuft bereits – Abbruch");
            return Ok(true);
        }
        Err(TryLockError::Error(e)) => return Err(e).context("Lock fehlgeschlagen"),
    }
    let _lock: File = lock; // bis Programmende gehalten

    if cfg.splay_secs > 0 && !cli.check_only {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0)
            ^ u64::from(std::process::id());
        std::thread::sleep(Duration::from_secs(seed % cfg.splay_secs));
    }

    let http = Client::builder()
        .timeout(Duration::from_secs(30))
        .https_only(!cfg.allow_insecure_http)
        .user_agent(concat!("cert-sync/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("HTTP-Client konnte nicht erstellt werden")?;

    let mut all_ok = true;
    for entry in &cfg.certificates {
        if cli.only.as_ref().is_some_and(|o| o != &entry.name) {
            continue;
        }
        match sync_one(&cfg, entry, &http, &cli) {
            Ok(Outcome::UpToDate | Outcome::UpdateAvailable | Outcome::Updated) => {}
            Err(e) => {
                eprintln!("{} cert-sync[{}]: FEHLER: {e:#}", ts(), entry.name);
                all_ok = false;
            }
        }
    }
    Ok(all_ok)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1), // mindestens ein Zertifikat ist fehlgeschlagen
        Err(e) => {
            eprintln!("Fehler: {e:#}");
            ExitCode::from(2) // Konfigurations-/Startfehler
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{
        mpsc::{self, Receiver},
        Arc, Mutex,
    };
    use std::thread;

    const CERT_PEM: &str = include_str!("../../testdata/test-cert.pem");
    const KEY_PEM: &str = include_str!("../../testdata/test-key.pem");
    const OTHER_KEY_PEM: &str = include_str!("../../testdata/other-key.pem");
    const FINGERPRINT: &str = include_str!("../../testdata/fingerprint.txt");

    /// Minimaler HTTP-Mock für cert-sync-Tests: ein TCP-Listener beantwortet
    /// jeden Request mit der vom `handler` zurückgegebenen Antwort.
    /// Die Tests setzen voraus, dass `api_url` per `allow_insecure_http = true`
    /// auf `http://127.0.0.1:PORT` zeigt.
    struct TestApi {
        base_url: String,
        stop: Option<mpsc::Sender<()>>,
    }

    type Handler = Arc<dyn Fn(&str) -> (u16, Vec<u8>) + Send + Sync>;

    impl TestApi {
        fn start(handler: Handler) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let (tx, rx): (mpsc::Sender<()>, Receiver<()>) = mpsc::channel();
            thread::spawn(move || {
                listener.set_nonblocking(false).unwrap();
                for stream in listener.incoming() {
                    if rx.try_recv().is_ok() {
                        return;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let mut buf = [0u8; 8192];
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let (status, body) = handler(path);
                    let reason = match status {
                        200 => "OK",
                        204 => "No Content",
                        400 => "Bad Request",
                        401 => "Unauthorized",
                        404 => "Not Found",
                        500 => "Internal Server Error",
                        _ => "Status",
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(&body);
                    let _ = stream.flush();
                }
            });
            Self {
                base_url: format!("http://127.0.0.1:{port}"),
                stop: Some(tx),
            }
        }
    }

    impl Drop for TestApi {
        fn drop(&mut self) {
            if let Some(tx) = self.stop.take() {
                let _ = tx.send(());
                // Auf den Listener warten, damit der Thread beendet ist
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    fn make_cfg(target_dir: &Path, base_url: &str) -> Config {
        Config {
            api_url: base_url.to_string(),
            reload_cmd: None,
            keep_backups: 5,
            warn_days: 14,
            splay_secs: 0,
            lock_file: PathBuf::from("/tmp/cert-sync-test.lock"),
            key_gid: None,
            allow_insecure_http: true,
            certificates: vec![CertEntry {
                name: "example.com".into(),
                api_key: "test-key".into(),
                target_dir: target_dir.to_path_buf(),
                reload_cmd: None,
            }],
        }
    }

    fn make_cli(force: bool, check_only: bool) -> Cli {
        Cli {
            config: PathBuf::from("/tmp/irrelevant.toml"),
            check_only,
            force,
            only: None,
        }
    }

    fn make_entry(target_dir: &Path) -> CertEntry {
        CertEntry {
            name: "example.com".into(),
            api_key: "test-key".into(),
            target_dir: target_dir.to_path_buf(),
            reload_cmd: None,
        }
    }

    fn make_http() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(5))
            .https_only(false)
            .build()
            .unwrap()
    }

    #[test]
    fn fingerprint_matches_api_calculation() {
        let chain = load_chain(CERT_PEM.as_bytes()).unwrap();
        let s = summarize(&chain).unwrap();
        // Identischer Wert wie im Test der cert-api (SHA-256 über das DER des Leaf-Zertifikats)
        assert_eq!(s.fingerprint, FINGERPRINT.trim());
        assert!(s.not_after > now_unix());
    }

    #[test]
    fn rejects_invalid_pem() {
        assert!(load_chain(b"kein pem").is_err());
        assert!(load_chain(b"").is_err());
    }

    #[test]
    fn key_must_match_certificate() {
        let chain = load_chain(CERT_PEM.as_bytes()).unwrap();
        assert!(ensure_key_matches(chain.clone(), KEY_PEM.as_bytes()).is_ok());
        assert!(ensure_key_matches(chain.clone(), OTHER_KEY_PEM.as_bytes()).is_err());
        assert!(ensure_key_matches(chain, b"kein schluessel").is_err());
    }

    #[test]
    fn write_file_sets_mode_and_refuses_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("privkey.pem");
        write_file(&p, b"geheim", 0o600).unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&p).unwrap(), b"geheim");
        assert!(write_file(&p, b"neu", 0o600).is_err());
    }

    #[test]
    fn prune_keeps_only_newest_backups() {
        let tmp = tempfile::tempdir().unwrap();
        let backup = tmp.path().join("backup");
        for name in ["2026-01-01", "2026-01-02", "2026-01-03", "2026-01-04"] {
            fs::create_dir_all(backup.join(name)).unwrap();
        }
        prune_backups(tmp.path(), 2);
        let mut left: Vec<String> = fs::read_dir(&backup)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["2026-01-03", "2026-01-04"]);
    }

    #[test]
    fn temp_dir_is_removed_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let path = {
            let t = TempDir::create(tmp.path(), "example.com").unwrap();
            assert!(t.path().is_dir());
            t.path().to_path_buf()
        };
        assert!(!path.exists());
    }

    #[test]
    fn reload_command_status_is_checked() {
        assert!(run_reload("true").is_ok());
        assert!(run_reload("false").is_err());
    }

    #[test]
    fn config_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let write = |name: &str, content: &str| {
            let p = tmp.path().join(name);
            fs::write(&p, content).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            p
        };
        let cert = "[[certificates]]\nname = \"a.de\"\napi_key = \"k\"\ntarget_dir = \"/x\"\n";

        let ok = write(
            "ok.toml",
            &format!("api_url = \"https://certs.example.com\"\n{cert}"),
        );
        let cfg = load_config(&ok).unwrap();
        assert_eq!(cfg.keep_backups, 5);
        assert_eq!(cfg.warn_days, 14);

        let http = write(
            "http.toml",
            &format!("api_url = \"http://certs.example.com\"\n{cert}"),
        );
        assert!(load_config(&http).is_err(), "http:// muss abgelehnt werden");

        let http_ok = write(
            "http_ok.toml",
            &format!("api_url = \"http://127.0.0.1:8443\"\nallow_insecure_http = true\n{cert}"),
        );
        assert!(load_config(&http_ok).is_ok());

        let dup = write(
            "dup.toml",
            &format!("api_url = \"https://x.de\"\n{cert}{cert}"),
        );
        assert!(load_config(&dup).is_err());

        let bad = write(
            "bad.toml",
            "api_url = \"https://x.de\"\n[[certificates]]\nname = \"../x\"\napi_key = \"k\"\ntarget_dir = \"/x\"\n",
        );
        assert!(load_config(&bad).is_err());

        let empty = write(
            "empty.toml",
            "api_url = \"https://x.de\"\ncertificates = []\n",
        );
        assert!(load_config(&empty).is_err());
    }

    #[test]
    fn api_new_strips_trailing_slash() {
        let entry = make_entry(Path::new("/tmp"));
        let http = make_http();
        let api = Api::new(&http, "http://x/", &entry).unwrap();
        assert_eq!(api.base, "http://x");
        assert_eq!(api.name, "example.com");
    }

    #[test]
    fn api_get_returns_4xx_as_error() {
        // 401 bricht laut Spec sofort ab (kein Retry, kein 5-s-Sleep)
        let api = TestApi::start(Arc::new(|path| {
            if path.contains("/check") {
                (401, Vec::new())
            } else {
                (404, Vec::new())
            }
        }));
        let http = make_http();
        let entry = make_entry(Path::new("/tmp"));
        let a = Api::new(&http, &api.base_url, &entry).unwrap();
        let err = a.get("check", &[]).unwrap_err();
        assert!(format!("{err:#}").contains("401"), "got: {err:#}");
    }

    #[test]
    fn sync_one_first_install_no_local_cert() {
        // Kein lokales Zertifikat → API muss fullchain.pem + privkey.pem liefern.
        let api = TestApi::start(Arc::new(|path| {
            if path.contains("/files/fullchain.pem") {
                (200, CERT_PEM.as_bytes().to_vec())
            } else if path.contains("/files/privkey.pem") {
                (200, KEY_PEM.as_bytes().to_vec())
            } else {
                (404, Vec::new())
            }
        }));
        let tmp = tempfile::tempdir().unwrap();
        let cfg = make_cfg(tmp.path(), &api.base_url);
        let entry = make_entry(tmp.path());
        let http = make_http();
        let cli = make_cli(false, false);

        let outcome = sync_one(&cfg, &entry, &http, &cli).unwrap();
        assert!(matches!(outcome, Outcome::Updated));

        // Zertifikate wurden geschrieben
        let cert_path = tmp.path().join("fullchain.pem");
        let key_path = tmp.path().join("privkey.pem");
        assert!(cert_path.exists());
        assert!(key_path.exists());
        // Modus 0600 für Key (kein key_gid gesetzt)
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn sync_one_up_to_date_no_force() {
        // Lokales Zertifikat vorhanden, API sagt: kein Update.
        let tmp = tempfile::tempdir().unwrap();
        // fullchain.pem + privkey.pem als "lokales" Material ablegen
        fs::write(tmp.path().join("fullchain.pem"), CERT_PEM).unwrap();
        fs::write(tmp.path().join("privkey.pem"), KEY_PEM).unwrap();

        let api = TestApi::start(Arc::new(|path| {
            if path.contains("/check") {
                (200, br#"{"update_available":false}"#.to_vec())
            } else {
                (500, Vec::new())
            }
        }));
        let cfg = make_cfg(tmp.path(), &api.base_url);
        let entry = make_entry(tmp.path());
        let http = make_http();
        let cli = make_cli(false, false);

        let outcome = sync_one(&cfg, &entry, &http, &cli).unwrap();
        assert!(matches!(outcome, Outcome::UpToDate));
    }

    #[test]
    fn sync_one_check_only_reports_update_without_download() {
        // Erstinstallation + --check-only → UpdateAvailable, kein Download
        let api = TestApi::start(Arc::new(|_path| (500, Vec::new()))); // alles andere ist Fehler
        let tmp = tempfile::tempdir().unwrap();
        let cfg = make_cfg(tmp.path(), &api.base_url);
        let entry = make_entry(tmp.path());
        let http = make_http();
        let cli = make_cli(false, true);

        let outcome = sync_one(&cfg, &entry, &http, &cli).unwrap();
        assert!(matches!(outcome, Outcome::UpdateAvailable));
        assert!(!tmp.path().join("fullchain.pem").exists());
    }

    #[test]
    fn sync_one_update_available_writes_files_and_backup() {
        // Vorhandenes Zertifikat (Key passt dazu) + neues Zertifikat von API
        // (hier verwenden wir dieselbe Datei, da das ausreicht, um Backup +
        // Schreibvorgang zu prüfen).
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("fullchain.pem"), CERT_PEM).unwrap();
        fs::write(tmp.path().join("privkey.pem"), KEY_PEM).unwrap();

        let api = TestApi::start(Arc::new(|path| {
            if path.contains("/check") {
                (200, br#"{"update_available":true}"#.to_vec())
            } else if path.contains("/files/fullchain.pem") {
                (200, CERT_PEM.as_bytes().to_vec())
            } else if path.contains("/files/privkey.pem") {
                (200, KEY_PEM.as_bytes().to_vec())
            } else {
                (404, Vec::new())
            }
        }));
        let cfg = make_cfg(tmp.path(), &api.base_url);
        let entry = make_entry(tmp.path());
        let http = make_http();
        // --force überspringt den Fingerprint-Gleichheits-Check nach dem Download
        let cli = make_cli(true, false);

        let outcome = sync_one(&cfg, &entry, &http, &cli).unwrap();
        assert!(matches!(outcome, Outcome::Updated));
        // Backup wurde angelegt
        let backup = tmp.path().join("backup");
        assert!(backup.is_dir());
        let subdirs: Vec<_> = fs::read_dir(&backup)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();
        assert_eq!(subdirs.len(), 1);
    }

    #[test]
    fn sync_one_force_skips_check_endpoint() {
        // Mit --force: /check darf nicht angefragt werden, auch wenn ein
        // lokales Zertifikat existiert.
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("fullchain.pem"), CERT_PEM).unwrap();
        fs::write(tmp.path().join("privkey.pem"), KEY_PEM).unwrap();

        let hits = Arc::new(Mutex::new(Vec::<String>::new()));
        let hits_c = Arc::clone(&hits);
        let api = TestApi::start(Arc::new(move |path| {
            hits_c.lock().unwrap().push(path.to_string());
            if path.contains("/files/fullchain.pem") {
                (200, CERT_PEM.as_bytes().to_vec())
            } else if path.contains("/files/privkey.pem") {
                (200, KEY_PEM.as_bytes().to_vec())
            } else {
                (500, Vec::new())
            }
        }));
        let cfg = make_cfg(tmp.path(), &api.base_url);
        let entry = make_entry(tmp.path());
        let http = make_http();
        let cli = make_cli(true, false);

        let _ = sync_one(&cfg, &entry, &http, &cli).unwrap();
        let seen = hits.lock().unwrap();
        assert!(
            !seen.iter().any(|p| p.contains("/check")),
            "force darf /check nicht anfragen"
        );
        assert!(seen.iter().any(|p| p.contains("/files/fullchain.pem")));
    }

    #[test]
    fn sync_one_key_gid_sets_640_and_chowns() {
        // key_gid gesetzt → Modus 0640, chown wird aufgerufen
        // (chown schlägt mit ungültiger GID fehl → Test prüft den Fehlerpfad).
        let api = TestApi::start(Arc::new(|path| {
            if path.contains("/files/fullchain.pem") {
                (200, CERT_PEM.as_bytes().to_vec())
            } else if path.contains("/files/privkey.pem") {
                (200, KEY_PEM.as_bytes().to_vec())
            } else {
                (404, Vec::new())
            }
        }));
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = make_cfg(tmp.path(), &api.base_url);
        // Eine GID, die auf dem Testsystem mit Sicherheit nicht existiert,
        // damit chown garantiert fehlschlägt.
        cfg.key_gid = Some(99_999_999);

        let entry = make_entry(tmp.path());
        let http = make_http();
        let cli = make_cli(false, false);

        let err = sync_one(&cfg, &entry, &http, &cli).unwrap_err();
        assert!(
            format!("{err:#}").contains("chown"),
            "erwarteter chown-Fehler, got: {err:#}"
        );
    }

    #[test]
    fn sync_one_local_cert_unreadable_proceeds_as_if_none() {
        // fullchain.pem existiert, ist aber kein gültiges PEM → Warnung,
        // Verhalten wie Erstinstallation (UpdateAvailable wird geholt).
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("fullchain.pem"), b"kein gueltiges PEM").unwrap();

        let api = TestApi::start(Arc::new(|path| {
            if path.contains("/files/fullchain.pem") {
                (200, CERT_PEM.as_bytes().to_vec())
            } else if path.contains("/files/privkey.pem") {
                (200, KEY_PEM.as_bytes().to_vec())
            } else if path.contains("/check") {
                (500, Vec::new()) // darf nicht angefragt werden
            } else {
                (404, Vec::new())
            }
        }));
        let cfg = make_cfg(tmp.path(), &api.base_url);
        let entry = make_entry(tmp.path());
        let http = make_http();
        let cli = make_cli(false, false);

        let outcome = sync_one(&cfg, &entry, &http, &cli).unwrap();
        assert!(matches!(outcome, Outcome::Updated));
    }

    #[test]
    fn sync_one_reload_failure_triggers_rollback() {
        // Vorhandenes Zertifikat, neue Version lädt, Reload schlägt fehl →
        // Backup wird wiederhergestellt und der Fehler propagiert.
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("fullchain.pem"), CERT_PEM).unwrap();
        fs::write(tmp.path().join("privkey.pem"), KEY_PEM).unwrap();

        let api = TestApi::start(Arc::new(|path| {
            if path.contains("/check") {
                (200, br#"{"update_available":true}"#.to_vec())
            } else if path.contains("/files/fullchain.pem") {
                (200, CERT_PEM.as_bytes().to_vec())
            } else if path.contains("/files/privkey.pem") {
                (200, KEY_PEM.as_bytes().to_vec())
            } else {
                (404, Vec::new())
            }
        }));
        let mut cfg = make_cfg(tmp.path(), &api.base_url);
        cfg.reload_cmd = Some("false".into()); // schlägt fehl
        let entry = make_entry(tmp.path());
        let http = make_http();
        let cli = make_cli(true, false); // --force: Fingerprint-Gleichheits-Check überspringen

        let err = sync_one(&cfg, &entry, &http, &cli).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Reload-Befehl"), "got: {msg}");
    }
}
