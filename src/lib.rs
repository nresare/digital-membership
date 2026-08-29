mod credential;
mod error;

use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::{Response, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blst::min_sig::SecretKey;
use qrcode_generator::Renderer;
use qrcode_generator::qr::{Encoder, ErrorCorrection};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::credential::{BLS_CIPHERSUITE, encode_credential};
use crate::error::AppError;

const KEY_ID: u8 = 0;
const QR_IMAGE_SIZE: usize = 768;

#[derive(Clone)]
pub struct AppState {
    signing_key: Arc<SecretKey>,
}

impl AppState {
    pub fn generate() -> anyhow::Result<Self> {
        let mut ikm = [0_u8; 32];
        getrandom::fill(&mut ikm)
            .map_err(|error| anyhow::anyhow!("failed to generate signing key material: {error}"))?;
        let signing_key = SecretKey::key_gen_v5(&ikm, &[], &[])
            .map_err(|error| anyhow::anyhow!("failed to generate BLS signing key: {error:?}"))?;
        Ok(Self {
            signing_key: Arc::new(signing_key),
        })
    }

    #[cfg(test)]
    fn from_signing_key(signing_key: SecretKey) -> Self {
        Self {
            signing_key: Arc::new(signing_key),
        }
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/qr", get(qr_code_get).post(qr_code_post))
        .route("/public-key", get(public_key))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
struct QrRequest {
    name: String,
    #[serde(default)]
    flags: Vec<u32>,
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

    for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "name" => {
                if name.replace(value.into_owned()).is_some() {
                    return Err(AppError::BadRequest(
                        "name must be provided exactly once".to_string(),
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
    Ok(QrRequest { name, flags })
}

fn generate_qr_code(state: &AppState, request: QrRequest) -> Result<Response<Body>, AppError> {
    let credential = encode_credential(
        &request.name,
        &request.flags,
        KEY_ID,
        state.signing_key.as_ref(),
    )?;
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

#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    algorithm: &'static str,
    key_id: u8,
    public_key: String,
}

async fn public_key(State(state): State<AppState>) -> Json<PublicKeyResponse> {
    Json(PublicKeyResponse {
        algorithm: BLS_CIPHERSUITE,
        key_id: KEY_ID,
        public_key: URL_SAFE_NO_PAD.encode(state.signing_key.sk_to_pk().to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::{AppState, app, parse_qr_query};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use blst::min_sig::SecretKey;
    use tower::ServiceExt;

    fn test_app() -> axum::Router {
        app(AppState::from_signing_key(
            SecretKey::key_gen_v5(&[7_u8; 32], &[], &[]).unwrap(),
        ))
    }

    #[tokio::test]
    async fn post_returns_png() {
        let response = test_app()
            .oneshot(
                Request::post("/qr")
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
                Request::get("/qr?name=Alice+Smith&flags=0%2C5&flags=9")
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

    #[tokio::test]
    async fn get_rejects_missing_name() {
        let response = test_app()
            .oneshot(Request::get("/qr?flags=0").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn exposes_public_key() {
        let response = test_app()
            .oneshot(Request::get("/public-key").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains(r#""algorithm":"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_""#));
        assert!(body.contains(r#""key_id":0"#));
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
    async fn rejects_invalid_credential_input() {
        let response = test_app()
            .oneshot(
                Request::post("/qr")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"","flags":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
