use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context};
use axum::{
    extract::{Path as UrlPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;
use tracing::{error, info, warn};
use x509_parser::extensions::GeneralName;

// ---------------------------------------------------------------------------
// Konfiguration
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Config {
    listen: SocketAddr,
    certificates: Vec<CertConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct CertConfig {
    name: String,
    api_key: String,
    /// certbot "live"-Verzeichnis (aktuelles Zertifikat)
    live_path: PathBuf,
    /// certbot "archive"-Verzeichnis (alle Versionen, auch abgelaufene)
    archive_path: Option<PathBuf>,
}

struct AppState {
    certs: HashMap<String, CertConfig>,
}

const PEM_PREFIXES: [&str; 4] = ["cert", "chain", "fullchain", "privkey"];

fn load_config(path: &str) -> anyhow::Result<Config> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Konfiguration '{path}' nicht lesbar"))?;
    let cfg: Config = toml::from_str(&raw).context("Konfiguration ungültig")?;

    if !cfg.listen.ip().is_loopback() {
        bail!("'listen' muss eine Loopback-Adresse sein (127.0.0.1 / ::1)");
    }
    if cfg.certificates.is_empty() {
        bail!("Keine [[certificates]] konfiguriert");
    }

    let mut seen = HashSet::new();
    for c in &cfg.certificates {
        let valid_name = !c.name.is_empty()
            && c.name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'));
        if !valid_name {
            bail!("Ungültiger Name '{}' (erlaubt: a-z A-Z 0-9 . - _)", c.name);
        }
        if c.api_key.len() < 32 {
            bail!("api_key für '{}' ist zu kurz (min. 32 Zeichen)", c.name);
        }
        if !seen.insert(c.name.clone()) {
            bail!("Name '{}' ist doppelt vergeben", c.name);
        }
    }
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Fehler
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    NotFound,
    BadRequest(String),
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

fn internal<E: std::fmt::Display>(e: E) -> ApiError {
    error!("interner Fehler: {e}");
    ApiError::Internal
}

// ---------------------------------------------------------------------------
// Authentifizierung (API-Key pro Zertifikat)
// ---------------------------------------------------------------------------

fn extract_key(headers: &HeaderMap) -> Option<&str> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.trim());
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
}

/// Prüft den Key gegen das angefragte Zertifikat. Unbekannte Namen und falsche Keys
/// liefern bewusst dieselbe 401-Antwort.
fn authorize<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    name: &str,
) -> Result<&'a CertConfig, ApiError> {
    let provided = extract_key(headers).ok_or(ApiError::Unauthorized)?;
    let cfg = state.certs.get(name).ok_or(ApiError::Unauthorized)?;
    if provided.as_bytes().ct_eq(cfg.api_key.as_bytes()).into() {
        Ok(cfg)
    } else {
        warn!("falscher API-Key für '{name}'");
        Err(ApiError::Unauthorized)
    }
}

// ---------------------------------------------------------------------------
// Zertifikats-Helfer
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CertInfo {
    subject: String,
    dns_names: Vec<String>,
    serial: String,
    fingerprint_sha256: String,
    not_before: String,
    not_after: String,
    not_after_unix: i64,
    expired: bool,
}

/// Liest das erste Zertifikat aus einer PEM-Datei (bei fullchain.pem das Leaf).
fn parse_cert_info(pem_bytes: &[u8]) -> anyhow::Result<CertInfo> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_bytes)
        .map_err(|e| anyhow!("PEM ungültig: {e:?}"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow!("X.509 ungültig: {e:?}"))?;

    let validity = cert.validity();
    let not_after_unix = validity.not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut dns_names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(n) = gn {
                dns_names.push(n.to_string());
            }
        }
    }

    Ok(CertInfo {
        subject: cert.subject().to_string(),
        dns_names,
        serial: cert.raw_serial_as_string(),
        fingerprint_sha256: hex::encode(Sha256::digest(&pem.contents)),
        not_before: validity
            .not_before
            .to_datetime()
            .format(&Rfc3339)
            .unwrap_or_default(),
        not_after: validity
            .not_after
            .to_datetime()
            .format(&Rfc3339)
            .unwrap_or_default(),
        not_after_unix,
        expired: not_after_unix < now,
    })
}

async fn read_file(path: &Path) -> Result<Vec<u8>, ApiError> {
    match tokio::fs::read(path).await {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ApiError::NotFound),
        Err(e) => Err(internal(format!("{}: {e}", path.display()))),
    }
}

async fn current_info(cfg: &CertConfig) -> Result<CertInfo, ApiError> {
    let bytes = read_file(&cfg.live_path.join("fullchain.pem")).await?;
    parse_cert_info(&bytes).map_err(internal)
}

fn pem_response(bytes: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response()
}

/// Nur feste Dateinamen für das "live"-Verzeichnis (verhindert Path Traversal).
fn live_file_allowed(file: &str) -> bool {
    matches!(file, "cert.pem" | "chain.pem" | "fullchain.pem" | "privkey.pem")
}

/// Archivdateien: <prefix><zahl>.pem, z.B. fullchain3.pem
fn archive_file_allowed(file: &str) -> bool {
    let Some(stem) = file.strip_suffix(".pem") else {
        return false;
    };
    PEM_PREFIXES.iter().any(|p| {
        stem.strip_prefix(p).is_some_and(|digits| {
            !digits.is_empty() && digits.len() <= 6 && digits.chars().all(|c| c.is_ascii_digit())
        })
    })
}

fn normalize_fingerprint(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

type Shared = State<Arc<AppState>>;

async fn health() -> &'static str {
    "ok"
}

/// GET /v1/certs/{name}/info
async fn info_handler(
    State(state): Shared,
    UrlPath(name): UrlPath<String>,
    headers: HeaderMap,
) -> Result<Json<CertInfo>, ApiError> {
    let cfg = authorize(&state, &headers, &name)?;
    Ok(Json(current_info(cfg).await?))
}

#[derive(Deserialize)]
struct CheckQuery {
    /// SHA-256-Fingerprint (hex) des Zertifikats, das der Client aktuell einsetzt
    fingerprint: Option<String>,
}

/// GET /v1/certs/{name}/check?fingerprint=<sha256-hex>
async fn check_handler(
    State(state): Shared,
    UrlPath(name): UrlPath<String>,
    Query(q): Query<CheckQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cfg = authorize(&state, &headers, &name)?;
    let client_fp = q
        .fingerprint
        .as_deref()
        .map(normalize_fingerprint)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::BadRequest("Query-Parameter 'fingerprint' fehlt".into()))?;

    let current = current_info(cfg).await?;
    Ok(Json(serde_json::json!({
        "update_available": client_fp != current.fingerprint_sha256,
        "current_fingerprint_sha256": current.fingerprint_sha256,
        "not_after": current.not_after,
        "expired": current.expired,
    })))
}

/// GET /v1/certs/{name}/files/{file}   (cert.pem | chain.pem | fullchain.pem | privkey.pem)
async fn live_file_handler(
    State(state): Shared,
    UrlPath((name, file)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let cfg = authorize(&state, &headers, &name)?;
    if !live_file_allowed(&file) {
        return Err(ApiError::NotFound);
    }
    Ok(pem_response(read_file(&cfg.live_path.join(&file)).await?))
}

/// GET /v1/certs/{name}/bundle  – alle aktuellen Dateien in einem JSON
async fn bundle_handler(
    State(state): Shared,
    UrlPath(name): UrlPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let cfg = authorize(&state, &headers, &name)?;

    let mut files = serde_json::Map::new();
    for f in ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"] {
        let bytes = read_file(&cfg.live_path.join(f)).await?;
        let text = String::from_utf8(bytes).map_err(internal)?;
        files.insert(f.to_string(), serde_json::Value::String(text));
    }
    let info = current_info(cfg).await?;

    let body = Json(serde_json::json!({ "info": info, "files": files }));
    Ok(([(header::CACHE_CONTROL, "no-store")], body).into_response())
}

#[derive(Serialize)]
struct ArchiveEntry {
    version: u32,
    info: CertInfo,
    files: Vec<String>,
}

/// GET /v1/certs/{name}/archive  – alle Versionen (aktuelle + abgelaufene)
async fn archive_list_handler(
    State(state): Shared,
    UrlPath(name): UrlPath<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<ArchiveEntry>>, ApiError> {
    let cfg = authorize(&state, &headers, &name)?;
    let dir = cfg.archive_path.as_ref().ok_or(ApiError::NotFound)?;

    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ApiError::NotFound),
        Err(e) => return Err(internal(e)),
    };

    let mut versions = Vec::new();
    while let Some(entry) = rd.next_entry().await.map_err(internal)? {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else { continue };
        if let Some(n) = fname
            .strip_prefix("cert")
            .and_then(|s| s.strip_suffix(".pem"))
            .and_then(|s| s.parse::<u32>().ok())
        {
            versions.push(n);
        }
    }
    versions.sort_unstable_by(|a, b| b.cmp(a)); // neueste zuerst

    let mut out = Vec::new();
    for v in versions {
        let bytes = match tokio::fs::read(dir.join(format!("cert{v}.pem"))).await {
            Ok(b) => b,
            Err(e) => {
                warn!("Archiv {name} v{v}: {e}");
                continue;
            }
        };
        let info = match parse_cert_info(&bytes) {
            Ok(i) => i,
            Err(e) => {
                warn!("Archiv {name} v{v}: {e}");
                continue;
            }
        };
        let mut files = Vec::new();
        for p in PEM_PREFIXES {
            let f = format!("{p}{v}.pem");
            if tokio::fs::try_exists(dir.join(&f)).await.unwrap_or(false) {
                files.push(f);
            }
        }
        out.push(ArchiveEntry { version: v, info, files });
    }
    Ok(Json(out))
}

/// GET /v1/certs/{name}/archive/{file}   (z.B. fullchain2.pem)
async fn archive_file_handler(
    State(state): Shared,
    UrlPath((name, file)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let cfg = authorize(&state, &headers, &name)?;
    let dir = cfg.archive_path.as_ref().ok_or(ApiError::NotFound)?;
    if !archive_file_allowed(&file) {
        return Err(ApiError::NotFound);
    }
    Ok(pem_response(read_file(&dir.join(&file)).await?))
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/certs/{name}/info", get(info_handler))
        .route("/v1/certs/{name}/check", get(check_handler))
        .route("/v1/certs/{name}/bundle", get(bundle_handler))
        .route("/v1/certs/{name}/files/{file}", get(live_file_handler))
        .route("/v1/certs/{name}/archive", get(archive_list_handler))
        .route("/v1/certs/{name}/archive/{file}", get(archive_file_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CERT_API_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".to_string());

    let cfg = load_config(&config_path)?;
    let listen = cfg.listen;
    let state = Arc::new(AppState {
        certs: cfg
            .certificates
            .into_iter()
            .map(|c| (c.name.clone(), c))
            .collect(),
    });
    info!("{} Zertifikat(e) konfiguriert", state.certs.len());

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("Bind auf {listen} fehlgeschlagen"))?;
    info!("lausche auf http://{listen}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use std::fs;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const CERT_PEM: &str = include_str!("../../testdata/test-cert.pem");
    const KEY_PEM: &str = include_str!("../../testdata/test-key.pem");
    const FINGERPRINT: &str = include_str!("../../testdata/fingerprint.txt");
    const API_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    fn expected_fp() -> &'static str {
        FINGERPRINT.trim()
    }

    /// Legt ein certbot-ähnliches live-/archive-Verzeichnis an und baut den Router.
    fn setup(with_archive: bool) -> (tempfile::TempDir, Router) {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("live");
        let archive = tmp.path().join("archive");
        fs::create_dir_all(&live).unwrap();
        fs::create_dir_all(&archive).unwrap();
        for f in ["cert.pem", "fullchain.pem", "chain.pem"] {
            fs::write(live.join(f), CERT_PEM).unwrap();
        }
        fs::write(live.join("privkey.pem"), KEY_PEM).unwrap();
        fs::write(archive.join("cert1.pem"), CERT_PEM).unwrap();
        fs::write(archive.join("fullchain1.pem"), CERT_PEM).unwrap();

        let mut certs = HashMap::new();
        certs.insert(
            "example.com".to_string(),
            CertConfig {
                name: "example.com".into(),
                api_key: API_KEY.into(),
                live_path: live,
                archive_path: with_archive.then_some(archive),
            },
        );
        (tmp, build_router(Arc::new(AppState { certs })))
    }

    async fn get_req(app: &Router, uri: &str, key: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::builder().uri(uri);
        if let Some(k) = key {
            req = req.header("x-api-key", k);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn parses_certificate_info() {
        let info = parse_cert_info(CERT_PEM.as_bytes()).unwrap();
        assert_eq!(info.fingerprint_sha256, expected_fp());
        assert!(info.subject.contains("test.example.com"));
        assert!(info.dns_names.contains(&"www.test.example.com".to_string()));
        assert!(!info.expired);
    }

    #[test]
    fn rejects_garbage_pem() {
        assert!(parse_cert_info(b"das ist kein zertifikat").is_err());
    }

    #[test]
    fn live_file_whitelist() {
        for ok in ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"] {
            assert!(live_file_allowed(ok));
        }
        for bad in ["../etc/passwd", "privkey1.pem", "", "cert.pem/", "config.toml"] {
            assert!(!live_file_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn archive_file_whitelist() {
        for ok in ["cert1.pem", "chain12.pem", "fullchain3.pem", "privkey999999.pem"] {
            assert!(archive_file_allowed(ok), "{ok}");
        }
        for bad in [
            "cert.pem",
            "cert.pem.bak",
            "../cert1.pem",
            "cert1/../../x.pem",
            "cert1234567.pem",
            "evil1.pem",
            "cert-1.pem",
        ] {
            assert!(!archive_file_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn fingerprint_normalization() {
        assert_eq!(normalize_fingerprint("AB:cd:EF"), "abcdef");
        assert_eq!(normalize_fingerprint("  12 34 "), "1234");
        assert_eq!(normalize_fingerprint(""), "");
    }

    #[test]
    fn api_key_from_headers() {
        let mut h = HeaderMap::new();
        assert!(extract_key(&h).is_none());
        h.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(extract_key(&h), Some("abc"));
        h.insert("x-api-key", " xyz ".parse().unwrap());
        assert_eq!(extract_key(&h), Some("xyz"));
    }

    #[tokio::test]
    async fn health_needs_no_key() {
        let (_t, app) = setup(false);
        let (status, body) = get_req(&app, "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn rejects_missing_wrong_and_unknown() {
        let (_t, app) = setup(false);
        let uri = "/v1/certs/example.com/info";
        assert_eq!(get_req(&app, uri, None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(get_req(&app, uri, Some("falsch")).await.0, StatusCode::UNAUTHORIZED);
        // unbekannter Name liefert dieselbe Antwort wie falscher Key
        let (status, _) = get_req(&app, "/v1/certs/gibts-nicht/info", Some(API_KEY)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn key_of_other_cert_is_rejected() {
        let (_t, app) = setup(false);
        // Router kennt nur example.com; fremder Key darf dort nicht funktionieren
        let (status, _) = get_req(&app, "/v1/certs/example.com/info", Some("anderer-key")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn info_returns_fingerprint() {
        let (_t, app) = setup(false);
        let (status, body) = get_req(&app, "/v1/certs/example.com/info", Some(API_KEY)).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["fingerprint_sha256"], expected_fp());
    }

    #[tokio::test]
    async fn check_detects_updates() {
        let (_t, app) = setup(false);
        let base = "/v1/certs/example.com/check";

        let (s, body) = get_req(&app, &format!("{base}?fingerprint={}", expected_fp()), Some(API_KEY)).await;
        assert_eq!(s, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["update_available"], false);

        let (_, body) = get_req(&app, &format!("{base}?fingerprint=deadbeef"), Some(API_KEY)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["update_available"], true);

        // Groß-/Kleinschreibung und Doppelpunkte werden toleriert
        let upper = expected_fp().to_uppercase();
        let (_, body) = get_req(&app, &format!("{base}?fingerprint={upper}"), Some(API_KEY)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["update_available"], false);

        let (s, _) = get_req(&app, base, Some(API_KEY)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn serves_live_files_only_from_whitelist() {
        let (_t, app) = setup(false);
        let (s, body) = get_req(&app, "/v1/certs/example.com/files/privkey.pem", Some(API_KEY)).await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("BEGIN PRIVATE KEY"));

        let (s, _) = get_req(&app, "/v1/certs/example.com/files/secret.txt", Some(API_KEY)).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = get_req(&app, "/v1/certs/example.com/files/privkey.pem", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bundle_contains_all_files() {
        let (_t, app) = setup(false);
        let (s, body) = get_req(&app, "/v1/certs/example.com/bundle", Some(API_KEY)).await;
        assert_eq!(s, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        for f in ["cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"] {
            assert!(v["files"][f].is_string(), "{f} fehlt");
        }
    }

    #[tokio::test]
    async fn archive_listing_and_download() {
        let (_t, app) = setup(true);
        let (s, body) = get_req(&app, "/v1/certs/example.com/archive", Some(API_KEY)).await;
        assert_eq!(s, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v[0]["version"], 1);
        assert_eq!(v[0]["info"]["fingerprint_sha256"], expected_fp());

        let (s, _) = get_req(&app, "/v1/certs/example.com/archive/fullchain1.pem", Some(API_KEY)).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = get_req(&app, "/v1/certs/example.com/archive/passwd", Some(API_KEY)).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn archive_is_404_without_archive_path() {
        let (_t, app) = setup(false);
        let (s, _) = get_req(&app, "/v1/certs/example.com/archive", Some(API_KEY)).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[test]
    fn config_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let write = |name: &str, content: &str| {
            let p = tmp.path().join(name);
            fs::write(&p, content).unwrap();
            p
        };
        let key = "k".repeat(32);

        let ok = write(
            "ok.toml",
            &format!("listen = \"127.0.0.1:8443\"\n[[certificates]]\nname = \"a.de\"\napi_key = \"{key}\"\nlive_path = \"/x\"\n"),
        );
        assert!(load_config(ok.to_str().unwrap()).is_ok());

        let public = write(
            "public.toml",
            &format!("listen = \"0.0.0.0:8443\"\n[[certificates]]\nname = \"a.de\"\napi_key = \"{key}\"\nlive_path = \"/x\"\n"),
        );
        assert!(load_config(public.to_str().unwrap()).is_err(), "nicht-loopback muss abgelehnt werden");

        let short = write(
            "short.toml",
            "listen = \"127.0.0.1:8443\"\n[[certificates]]\nname = \"a.de\"\napi_key = \"kurz\"\nlive_path = \"/x\"\n",
        );
        assert!(load_config(short.to_str().unwrap()).is_err());

        let dup = write(
            "dup.toml",
            &format!("listen = \"127.0.0.1:8443\"\n[[certificates]]\nname = \"a.de\"\napi_key = \"{key}\"\nlive_path = \"/x\"\n[[certificates]]\nname = \"a.de\"\napi_key = \"{key}\"\nlive_path = \"/y\"\n"),
        );
        assert!(load_config(dup.to_str().unwrap()).is_err());

        let bad_name = write(
            "bad.toml",
            &format!("listen = \"127.0.0.1:8443\"\n[[certificates]]\nname = \"../x\"\napi_key = \"{key}\"\nlive_path = \"/x\"\n"),
        );
        assert!(load_config(bad_name.to_str().unwrap()).is_err());
    }
}
