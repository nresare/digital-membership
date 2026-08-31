mod credential;
mod error;
mod issuer;
mod signing;
mod wallet;

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderValue, Response, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use qrcode_generator::Renderer;
use qrcode_generator::qr::{Encoder, ErrorCorrection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::credential::{BLS_CIPHERSUITE, Identifier, encode_credential, issue_day_now};
use crate::error::AppError;
use crate::issuer::{FlagRef, Issuer};
use crate::wallet::WalletPass;

pub use crate::issuer::IssuerConfig;
pub use crate::signing::SigningKey;
pub use crate::wallet::WalletConfig;

const QR_IMAGE_SIZE: usize = 768;

#[cfg(test)]
fn test_name_model() -> namecompress::Table {
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
    issuers: Arc<BTreeMap<String, Issuer>>,
    wallet: Option<Arc<WalletPass>>,
}

impl AppState {
    pub fn load(issuers: Vec<IssuerConfig>, wallet: Option<WalletConfig>) -> anyhow::Result<Self> {
        let issuers = issuers
            .into_iter()
            .map(|config| Ok((config.id.clone(), Issuer::load(config)?)))
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let wallet = wallet.map(WalletPass::load).transpose()?.map(Arc::new);
        Ok(Self {
            issuers: Arc::new(issuers),
            wallet,
        })
    }

    /// The configured issuer ids, in the order they are served.
    pub fn issuer_ids(&self) -> impl Iterator<Item = &str> {
        self.issuers.keys().map(String::as_str)
    }

    fn issuer(&self, id: &str) -> Result<&Issuer, AppError> {
        self.issuers
            .get(id)
            .ok_or_else(|| AppError::NotFound(format!("no issuer '{id}' is configured")))
    }

    #[cfg(test)]
    fn from_issuer(issuer: Issuer) -> Self {
        Self {
            issuers: Arc::new(BTreeMap::from([(issuer.id.clone(), issuer)])),
            wallet: None,
        }
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/setup", get(setup))
        .route("/healthz", get(healthz))
        .route("/api/{issuer}/qr", get(qr_code_get).post(qr_code_post))
        .route("/api/{issuer}/wallet", get(wallet_pass_get))
        .route("/api/{issuer}/provision", get(provision))
        .route("/api/{issuer}/model/model.ncmp.xz", get(name_model))
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
    flags: Vec<FlagRef>,
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
    Path(issuer): Path<String>,
    Json(request): Json<QrRequest>,
) -> Result<Response<Body>, AppError> {
    generate_qr_code(state.issuer(&issuer)?, &request)
}

async fn qr_code_get(
    State(state): State<AppState>,
    Path(issuer): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Response<Body>, AppError> {
    let request = parse_qr_query(query.as_deref())?;
    generate_qr_code(state.issuer(&issuer)?, &request)
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
                flags.extend(value.split(',').map(FlagRef::parse));
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

fn generate_qr_code(issuer: &Issuer, request: &QrRequest) -> Result<Response<Body>, AppError> {
    let credential = generate_credential(issuer, request)?;
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
    Path(issuer): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Response<Body>, AppError> {
    let request = parse_qr_query(query.as_deref())?;
    let issuer = state.issuer(&issuer)?;
    let wallet = state.wallet.as_ref().ok_or_else(|| {
        AppError::Unavailable("Apple Wallet support is not configured".to_string())
    })?;
    let credential = generate_credential(issuer, &request)?;
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

fn generate_credential(issuer: &Issuer, request: &QrRequest) -> Result<Vec<u8>, AppError> {
    encode_credential(
        &request.name,
        &issuer.resolve_flags(&request.flags)?,
        &request.identifier()?,
        issue_day_now()?,
        &issuer.name_model,
        issuer.signing_key.secret(),
    )
}

/// The bootstrap document at `/setup`: enough for a scanner to list the issuers
/// this service signs for and let someone pick one, without knowing any of their
/// ids in advance.
#[derive(Debug, Serialize)]
struct SetupResponse {
    issuers: Vec<SetupIssuer>,
}

#[derive(Debug, Serialize)]
struct SetupIssuer {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// Where to fetch this issuer's provisioning metadata, relative to the
    /// service origin.
    provision_url: String,
}

async fn setup(State(state): State<AppState>) -> Json<SetupResponse> {
    Json(SetupResponse {
        issuers: state
            .issuers
            .values()
            .map(|issuer| SetupIssuer {
                id: issuer.id.clone(),
                name: issuer.name.clone(),
                description: issuer.description.clone(),
                provision_url: issuer.provision_url(),
            })
            .collect(),
    })
}

#[derive(Debug, Serialize)]
struct ProvisionResponse {
    algorithm: &'static str,
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    name_model_id: u32,
    name_model_url: String,
    public_key: String,
    /// Flag labels, where the position in the list is the flag number and an
    /// empty label means that number has no name.
    flags: Vec<String>,
}

async fn provision(
    State(state): State<AppState>,
    Path(issuer): Path<String>,
) -> Result<Json<ProvisionResponse>, AppError> {
    let issuer = state.issuer(&issuer)?;
    Ok(Json(ProvisionResponse {
        algorithm: BLS_CIPHERSUITE,
        id: issuer.id.clone(),
        name: issuer.name.clone(),
        description: issuer.description.clone(),
        name_model_id: issuer.name_model.id,
        name_model_url: issuer.name_model_url(),
        public_key: issuer.signing_key.public_key_base64(),
        flags: issuer.flags.clone(),
    }))
}

async fn name_model(
    State(state): State<AppState>,
    Path(issuer): Path<String>,
) -> Result<Response<Body>, AppError> {
    let model = Arc::clone(&state.issuer(&issuer)?.compressed_name_model);
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/x-xz")
        .body(Body::from(Bytes::from_owner(model)))
        .expect("static name model response is valid"))
}

#[cfg(test)]
mod tests {
    use super::{AppState, app, parse_qr_query, test_name_model};
    use crate::issuer::{FlagRef, Issuer};
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use blst::min_sig::SecretKey;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use tower::ServiceExt;
    use xz2::read::XzDecoder;
    use xz2::write::XzEncoder;

    const XZ_MAGIC: &[u8] = b"\xfd7zXZ\0";

    fn test_issuer() -> Issuer {
        let model = test_name_model();
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&model.write()).unwrap();
        Issuer {
            id: "example".to_string(),
            name: "Example Membership Society".to_string(),
            description: None,
            signing_key: SecretKey::key_gen_v5(&[7_u8; 32], &[], &[]).unwrap().into(),
            name_model: model,
            compressed_name_model: encoder.finish().unwrap().into(),
            flags: vec![
                "member".to_string(),
                String::new(),
                "vegetarian".to_string(),
            ],
        }
    }

    fn test_app() -> axum::Router {
        app(AppState::from_issuer(test_issuer()))
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let response = test_app()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_returns_png() {
        let response = test_app()
            .oneshot(
                Request::post("/api/example/qr")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"Alice","flags":[0,"vegetarian",9]}"#))
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
                Request::get("/api/example/qr?name=Alice+Smith&flags=member%2C5&flags=9")
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

    #[tokio::test]
    async fn an_unknown_issuer_is_not_found() {
        for path in [
            "/api/choir/qr?name=Alice",
            "/api/choir/provision",
            "/api/choir/model/model.ncmp.xz",
        ] {
            let response = test_app()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn rejects_a_flag_label_the_issuer_does_not_define() {
        let response = test_app()
            .oneshot(
                Request::get("/api/example/qr?name=Alice&flags=committee")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parses_repeated_and_comma_separated_flags() {
        let request = parse_qr_query(Some("name=Alice+Smith&flags=member%2C5&flags=9")).unwrap();

        assert_eq!(request.name, "Alice Smith");
        assert_eq!(
            request.flags,
            [
                FlagRef::Label("member".to_string()),
                FlagRef::Number(5),
                FlagRef::Number(9)
            ]
        );
    }

    #[test]
    fn parses_either_form_of_member_identifier() {
        use crate::credential::Identifier;

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
            .oneshot(
                Request::get("/api/example/qr?flags=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wallet_endpoint_reports_missing_configuration() {
        let response = test_app()
            .oneshot(
                Request::get("/api/example/wallet?name=Alice")
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
            .oneshot(
                Request::get("/api/example/provision")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains(r#""algorithm":"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_""#));
        assert!(body.contains(r#""id":"example""#));
        assert!(body.contains(r#""name":"Example Membership Society""#));
        // The issuer configures no description, so the key is left out.
        assert!(!body.contains(r#""description""#), "{body}");
        assert!(body.contains(r#""name_model_id":"#));
        assert!(body.contains(r#""name_model_url":"/api/example/model/model.ncmp.xz""#));
        assert!(body.contains(r#""flags":["member","","vegetarian"]"#));
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
                Request::get("/api/example/model/model.ncmp.xz")
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

    #[tokio::test]
    async fn setup_lists_every_issuer_with_a_link_to_its_provisioning_metadata() {
        let mut choir = test_issuer();
        choir.id = "choir".to_string();
        choir.name = "Example Choral Society".to_string();
        choir.description = Some("Sings on Tuesdays".to_string());
        let state = AppState {
            issuers: Arc::new(
                [test_issuer(), choir]
                    .into_iter()
                    .map(|issuer| (issuer.id.clone(), issuer))
                    .collect(),
            ),
            wallet: None,
        };

        let response = app(state)
            .oneshot(Request::get("/setup").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            String::from_utf8(body.to_vec()).unwrap(),
            concat!(
                r#"{"issuers":["#,
                r#"{"id":"choir","name":"Example Choral Society","#,
                r#""description":"Sings on Tuesdays","#,
                r#""provision_url":"/api/choir/provision"},"#,
                r#"{"id":"example","name":"Example Membership Society","#,
                r#""provision_url":"/api/example/provision"}"#,
                r#"]}"#
            )
        );
    }

    #[tokio::test]
    async fn setup_needs_no_issuer_in_its_path() {
        // The whole point is that a scanner can reach it knowing only the
        // origin, so it must not sit under /api/{issuer}/.
        let response = test_app()
            .oneshot(Request::get("/api/setup").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn each_issuer_signs_with_its_own_key() {
        let mut choir = test_issuer();
        choir.id = "choir".to_string();
        choir.name = "Example Choral Society".to_string();
        choir.signing_key = SecretKey::key_gen_v5(&[9_u8; 32], &[], &[]).unwrap().into();
        let expected = choir.signing_key.public_key_base64();
        let state = AppState {
            issuers: Arc::new(
                [test_issuer(), choir]
                    .into_iter()
                    .map(|issuer| (issuer.id.clone(), issuer))
                    .collect(),
            ),
            wallet: None,
        };
        assert_eq!(state.issuer_ids().collect::<Vec<_>>(), ["choir", "example"]);

        let response = app(state)
            .oneshot(
                Request::get("/api/choir/provision")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body.contains(&format!(r#""public_key":"{expected}""#)),
            "{body}"
        );
        assert!(body.contains(r#""name_model_url":"/api/choir/model/model.ncmp.xz""#));
    }

    #[tokio::test]
    async fn rejects_invalid_credential_input() {
        let response = test_app()
            .oneshot(
                Request::post("/api/example/qr")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"name":"","flags":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
