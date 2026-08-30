mod credential;
mod error;
mod signing;
mod wallet;

use axum::body::{Body, Bytes};
use axum::extract::{RawQuery, State};
use axum::http::{HeaderValue, Response, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use namecompress::Table;
use qrcode_generator::Renderer;
use qrcode_generator::qr::{Encoder, ErrorCorrection};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;

use crate::credential::{BLS_CIPHERSUITE, Identifier, encode_credential, issue_day_now};
use crate::error::AppError;
use crate::wallet::WalletPass;

pub use crate::signing::SigningKey;
pub use crate::wallet::WalletConfig;

const KEY_ID: u8 = 0;
const QR_IMAGE_SIZE: usize = 768;
const NAME_MODEL_URL: &str = "/api/model/model.ncmp.xz";
const XZ_MAGIC: &[u8] = b"\xfd7zXZ\0";

#[cfg(test)]
fn test_name_model() -> Table {
    use namecompress::TableBuilder;
    use namecompress::chars::{Alphabet, CharModelBuilder};

    let alphabet = Alphabet::new("abcdefghijklmnopqrstuvwxyz -'".chars().collect()).unwrap();
    let mut builder = CharModelBuilder::new(alphabet.symbols());
    for name in ["alice", "john", "smith", "jones"] {
        builder.train(&alphabet.encode(name).unwrap(), 100);
    }
    TableBuilder {
        given: vec![("Alice".into(), 300), ("John".into(), 500)],
        given_escape: 100,
        surname: vec![("Smith".into(), 400), ("Jones".into(), 200)],
        surname_escape: 100,
        alphabet,
        chars: builder.build(0),
        check_modulus: 256,
    }
    .finish()
}

#[derive(Clone)]
pub struct AppState {
    signing_key: Arc<SigningKey>,
    name_model: Arc<Table>,
    compressed_name_model: Arc<[u8]>,
    wallet: Option<Arc<WalletPass>>,
}

impl AppState {
    pub fn generate(name_model_path: &Path) -> anyhow::Result<Self> {
        Self::generate_with_wallet(name_model_path, None)
    }

    pub fn generate_with_wallet(
        name_model_path: &Path,
        wallet_config: Option<WalletConfig>,
    ) -> anyhow::Result<Self> {
        let configured_name_model = std::fs::read(name_model_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to read name model '{}': {error}",
                name_model_path.display()
            )
        })?;
        let (name_model_bytes, compressed_name_model) =
            if configured_name_model.starts_with(XZ_MAGIC) {
                let mut decompressed = Vec::new();
                XzDecoder::new(configured_name_model.as_slice())
                    .read_to_end(&mut decompressed)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "failed to decompress xz name model '{}': {error}",
                            name_model_path.display()
                        )
                    })?;
                (decompressed, configured_name_model)
            } else {
                let mut encoder = XzEncoder::new(Vec::new(), 6);
                encoder.write_all(&configured_name_model).map_err(|error| {
                    anyhow::anyhow!(
                        "failed to compress name model '{}': {error}",
                        name_model_path.display()
                    )
                })?;
                let compressed = encoder.finish().map_err(|error| {
                    anyhow::anyhow!(
                        "failed to finish compressing name model '{}': {error}",
                        name_model_path.display()
                    )
                })?;
                (configured_name_model, compressed)
            };
        let name_model = Table::load(&name_model_bytes).map_err(|error| {
            anyhow::anyhow!(
                "failed to load name model '{}': {error}",
                name_model_path.display()
            )
        })?;

        let signing_key = SigningKey::generate()?;
        let wallet = wallet_config
            .map(WalletPass::load)
            .transpose()?
            .map(Arc::new);
        Ok(Self {
            signing_key: Arc::new(signing_key),
            name_model: Arc::new(name_model),
            compressed_name_model: compressed_name_model.into(),
            wallet,
        })
    }

    #[cfg(test)]
    fn from_signing_key(signing_key: SigningKey, name_model: Table) -> Self {
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&name_model.write()).unwrap();
        let compressed_name_model = encoder.finish().unwrap();
        Self {
            signing_key: Arc::new(signing_key),
            name_model: Arc::new(name_model),
            compressed_name_model: compressed_name_model.into(),
            wallet: None,
        }
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/healthz", get(healthz))
        .route("/api/qr", get(qr_code_get).post(qr_code_post))
        .route("/api/wallet", get(wallet_pass_get))
        .route("/api/provision", get(provision))
        .route(NAME_MODEL_URL, get(name_model))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QrRequest {
    name: String,
    #[serde(default)]
    flags: Vec<u32>,
    /// A textual member identifier. Mutually exclusive with `member_number`.
    #[serde(default)]
    member_id: Option<String>,
    /// A numeric member identifier, which encodes more compactly than the same
    /// digits as text. Mutually exclusive with `member_id`.
    #[serde(default)]
    member_number: Option<u64>,
}

impl QrRequest {
    fn identifier(&self) -> Result<Identifier, AppError> {
        match (&self.member_id, self.member_number) {
            (Some(_), Some(_)) => Err(AppError::BadRequest(
                "member_id and member_number must not both be provided".to_string(),
            )),
            (Some(text), None) => Ok(Identifier::Text(text.clone())),
            (None, Some(number)) => Ok(Identifier::Number(number)),
            (None, None) => Ok(Identifier::None),
        }
    }
}

async fn qr_code_post(
    State(state): State<AppState>,
    Json(request): Json<QrRequest>,
) -> Result<Response<Body>, AppError> {
    generate_qr_code(&state, request)
}

async fn qr_code_get(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Result<Response<Body>, AppError> {
    let request = parse_qr_query(query.as_deref())?;
    generate_qr_code(&state, request)
}

fn parse_qr_query(query: Option<&str>) -> Result<QrRequest, AppError> {
    let mut name = None;
    let mut flags = Vec::new();
    let mut member_id = None;
    let mut member_number = None;

    for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "name" => {
                if name.replace(value.into_owned()).is_some() {
                    return Err(AppError::BadRequest(
                        "name must be provided exactly once".to_string(),
                    ));
                }
            }
            "member_id" => {
                if member_id.replace(value.into_owned()).is_some() {
                    return Err(AppError::BadRequest(
                        "member_id must be provided at most once".to_string(),
                    ));
                }
            }
            "member_number" => {
                let number = value.parse::<u64>().map_err(|_| {
                    AppError::BadRequest("member_number must be a non-negative integer".to_string())
                })?;
                if member_number.replace(number).is_some() {
                    return Err(AppError::BadRequest(
                        "member_number must be provided at most once".to_string(),
                    ));
                }
            }
            "flags" if value.is_empty() => {}
            "flags" => {
                for value in value.split(',') {
                    let flag = value.parse::<u32>().map_err(|_| {
                        AppError::BadRequest(
                            "flags must be non-negative integers; use repeated parameters or a comma-separated list"
                                .to_string(),
                        )
                    })?;
                    flags.push(flag);
                }
            }
            parameter => {
                return Err(AppError::BadRequest(format!(
                    "unknown query parameter '{parameter}'"
                )));
            }
        }
    }

    let name =
        name.ok_or_else(|| AppError::BadRequest("name query parameter is required".to_string()))?;
    Ok(QrRequest {
        name,
        flags,
        member_id,
        member_number,
    })
}

fn generate_qr_code(state: &AppState, request: QrRequest) -> Result<Response<Body>, AppError> {
    let credential = generate_credential(state, &request)?;
    let symbol = Encoder::new(ErrorCorrection::Medium)
        .encode_bytes(&credential)
        .map_err(|error| AppError::Internal(format!("failed to encode QR code: {error}")))?;
    let png = Renderer::new(&symbol, QR_IMAGE_SIZE)
        .to_png_vec()
        .map_err(|error| AppError::Internal(format!("failed to render QR code: {error}")))?;

    Response::builder()
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(png))
        .map_err(|error| AppError::Internal(format!("failed to build response: {error}")))
}

async fn wallet_pass_get(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Result<Response<Body>, AppError> {
    let request = parse_qr_query(query.as_deref())?;
    let wallet = state.wallet.as_ref().ok_or_else(|| {
        AppError::Unavailable("Apple Wallet support is not configured".to_string())
    })?;
    let credential = generate_credential(&state, &request)?;
    let pass = wallet
        .build(&request.name, &credential)
        .map_err(|error| AppError::Internal(format!("failed to build Wallet pass: {error:#}")))?;

    Response::builder()
        .header(header::CONTENT_TYPE, "application/vnd.apple.pkpass")
        .header(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=membership.pkpass"),
        )
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .body(Body::from(pass))
        .map_err(|error| AppError::Internal(format!("failed to build response: {error}")))
}

fn generate_credential(state: &AppState, request: &QrRequest) -> Result<Vec<u8>, AppError> {
    encode_credential(
        &request.name,
        &request.flags,
        &request.identifier()?,
        issue_day_now()?,
        KEY_ID,
        state.name_model.as_ref(),
        state.signing_key.secret(),
    )
}

#[derive(Debug, Serialize)]
struct ProvisionResponse {
    algorithm: &'static str,
    key_id: u8,
    name_model_id: u32,
    name_model_url: &'static str,
    public_key: String,
}

async fn provision(State(state): State<AppState>) -> Json<ProvisionResponse> {
    Json(ProvisionResponse {
        algorithm: BLS_CIPHERSUITE,
        key_id: KEY_ID,
        name_model_id: state.name_model.id,
        name_model_url: NAME_MODEL_URL,
        public_key: state.signing_key.public_key_base64(),
    })
}

async fn name_model(State(state): State<AppState>) -> Response<Body> {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/x-xz")
        .body(Body::from(Bytes::from_owner(state.compressed_name_model)))
        .expect("static name model response is valid")
}

#[cfg(test)]
mod tests {
    use super::{AppState, Identifier, XZ_MAGIC, app, parse_qr_query, test_name_model};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use blst::min_sig::SecretKey;
    use std::io::Read;
    use tower::ServiceExt;
    use xz2::read::XzDecoder;

    fn test_app() -> axum::Router {
        app(AppState::from_signing_key(
            SecretKey::key_gen_v5(&[7_u8; 32], &[], &[]).unwrap().into(),
            test_name_model(),
        ))
    }

    #[tokio::test]
    async fn post_returns_png() {
        let response = test_app()
            .oneshot(
                Request::post("/api/qr")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"Alice","flags":[0,5,9]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
    }

    #[tokio::test]
    async fn get_returns_png_for_url_encoded_query() {
        let response = test_app()
            .oneshot(
                Request::get("/api/qr?name=Alice+Smith&flags=0%2C5&flags=9")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
    }

    #[test]
    fn parses_repeated_and_comma_separated_flags() {
        let request = parse_qr_query(Some("name=Alice+Smith&flags=0%2C5&flags=9")).unwrap();

        assert_eq!(request.name, "Alice Smith");
        assert_eq!(request.flags, [0, 5, 9]);
    }

    #[test]
    fn parses_either_form_of_member_identifier() {
        let request = parse_qr_query(Some("name=Alice&member_number=4242")).unwrap();
        assert_eq!(request.identifier().unwrap(), Identifier::Number(4242));

        let request = parse_qr_query(Some("name=Alice&member_id=AB-99")).unwrap();
        assert_eq!(
            request.identifier().unwrap(),
            Identifier::Text("AB-99".to_string())
        );

        let request = parse_qr_query(Some("name=Alice")).unwrap();
        assert_eq!(request.identifier().unwrap(), Identifier::None);
    }

    #[test]
    fn rejects_conflicting_or_malformed_member_identifiers() {
        let request = parse_qr_query(Some("name=Alice&member_id=AB-99&member_number=42")).unwrap();
        assert!(request.identifier().is_err());

        assert!(parse_qr_query(Some("name=Alice&member_number=AB-99")).is_err());
        assert!(parse_qr_query(Some("name=Alice&member_id=a&member_id=b")).is_err());
    }

    #[tokio::test]
    async fn get_rejects_missing_name() {
        let response = test_app()
            .oneshot(Request::get("/api/qr?flags=0").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wallet_endpoint_reports_missing_configuration() {
        let response = test_app()
            .oneshot(
                Request::get("/api/wallet?name=Alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn exposes_provisioning_metadata() {
        let response = test_app()
            .oneshot(Request::get("/api/provision").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains(r#""algorithm":"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_""#));
        assert!(body.contains(r#""key_id":0"#));
        assert!(body.contains(r#""name_model_id":"#));
        assert!(body.contains(r#""name_model_url":"/api/model/model.ncmp.xz""#));
        let public_key = body
            .split_once(r#""public_key":""#)
            .unwrap()
            .1
            .split_once('"')
            .unwrap()
            .0;
        assert_eq!(URL_SAFE_NO_PAD.decode(public_key).unwrap().len(), 96);
    }

    #[tokio::test]
    async fn serves_name_model_referenced_by_provisioning_metadata() {
        let expected_model = test_name_model();
        let response = test_app()
            .oneshot(
                Request::get("/api/model/model.ncmp.xz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/x-xz");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(XZ_MAGIC));
        let mut decompressed = Vec::new();
        XzDecoder::new(body.as_ref())
            .read_to_end(&mut decompressed)
            .unwrap();
        let downloaded_model = namecompress::Table::load(&decompressed).unwrap();
        assert_eq!(downloaded_model.id, expected_model.id);
    }

    #[test]
    fn loads_configured_name_model() {
        let model = test_name_model();
        let path = std::env::temp_dir().join(format!(
            "digital-membership-name-model-{}.ncmp",
            std::process::id()
        ));
        let model_bytes = model.write();
        assert_eq!(&model_bytes[..6], b"NCMP\x01\0");
        std::fs::write(&path, model_bytes).unwrap();

        let state = AppState::generate(&path).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(state.name_model.id, model.id);
        assert!(state.compressed_name_model.starts_with(XZ_MAGIC));
    }

    #[test]
    fn loads_xz_compressed_name_model() {
        use std::io::Write;
        use xz2::write::XzEncoder;

        let model = test_name_model();
        let path = std::env::temp_dir().join(format!(
            "digital-membership-name-model-{}.ncmp.xz",
            std::process::id()
        ));
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&model.write()).unwrap();
        let compressed = encoder.finish().unwrap();
        std::fs::write(&path, &compressed).unwrap();

        let state = AppState::generate(&path).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(state.name_model.id, model.id);
        assert_eq!(state.compressed_name_model.as_ref(), compressed);
    }

    #[tokio::test]
    async fn rejects_invalid_credential_input() {
        let response = test_app()
            .oneshot(
                Request::post("/api/qr")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"","flags":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
