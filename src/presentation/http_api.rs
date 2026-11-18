use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    application::eco_vision_service::{ApplicationError, EcoVisionService},
    contracts::api_contracts::{
        ApiError, AuditSummary, AuthCredentials, ChangePasswordRequest, CitizenPrivacyStatus,
        CreateReport, Dashboard, LoginCredentials, RecoveryCodes, ReportReceipt, ReportSummary,
        SecurityDashboard, SecurityScanRequest, SecurityScanResponse, Severity,
        TwoFactorCodeRequest, TwoFactorDisableRequest, TwoFactorSetup, TwoFactorSetupRequest,
        TwoFactorStatus, UserProfile, WeatherSummary,
    },
    domain::pii_detector::PiiKind,
    security::taint_policy::{DataOrigin, DataSink, TaintDecision},
};

#[derive(Clone)]
pub struct AppState {
    service: EcoVisionService,
}

impl AppState {
    pub fn new(service: EcoVisionService) -> Self {
        Self { service }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/admin", get(admin_index))
        .route("/assets/Dashboard.css", get(dashboard_styles))
        .route("/assets/Dashboard.js", get(dashboard_script))
        .route("/assets/AdminDashboard.css", get(admin_dashboard_styles))
        .route("/assets/AdminDashboard.js", get(admin_dashboard_script))
        .route("/health", get(health))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(auth_me))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/password", post(change_password))
        .route("/api/v1/auth/2fa/status", get(two_factor_status))
        .route("/api/v1/auth/2fa/setup", post(start_two_factor_setup))
        .route("/api/v1/auth/2fa/confirm", post(confirm_two_factor_setup))
        .route("/api/v1/auth/2fa/disable", post(disable_two_factor))
        .route("/api/v1/dashboard", get(dashboard))
        .route("/api/v1/privacy/status", get(privacy_status))
        .route("/api/v1/reports", get(list_reports).post(create_report))
        .route("/api/v1/weather", get(weather))
        .route("/api/v1/security/dashboard", get(security_dashboard))
        .route("/api/v1/security/scan", post(security_scan))
        .route("/api/v1/security/audit", get(security_audit))
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn(security_headers))
        .layer(axum::extract::DefaultBodyLimit::max(32 * 1024))
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"),
    );
    response
}

#[derive(OpenApi)]
#[openapi(
    paths(health, register, login, auth_me, logout, change_password, two_factor_status, start_two_factor_setup, confirm_two_factor_setup, disable_two_factor, dashboard, privacy_status, list_reports, create_report, weather, security_dashboard, security_scan, security_audit),
    components(schemas(
        ApiError, ReportSummary, CreateReport, ReportReceipt, Severity,
        Dashboard, CitizenPrivacyStatus, SecurityDashboard, WeatherSummary, SecurityScanRequest, SecurityScanResponse,
        AuditSummary, AuthCredentials, LoginCredentials, ChangePasswordRequest, TwoFactorSetupRequest,
        TwoFactorCodeRequest, TwoFactorDisableRequest, TwoFactorStatus, TwoFactorSetup, RecoveryCodes,
        UserProfile, TaintDecision, DataOrigin, DataSink, PiiKind
    )),
    tags((name = "Eco Vision", description = "Monitoramento comunitário e segurança dos dados"))
)]
struct ApiDoc;

async fn index() -> Html<&'static str> {
    Html(include_str!("../../frontend/Index.html"))
}

async fn admin_index() -> Html<&'static str> {
    Html(include_str!("../../frontend/Admin.html"))
}

async fn dashboard_styles() -> Response<Body> {
    static_asset(
        "text/css; charset=utf-8",
        include_str!("../../frontend/Dashboard.css"),
    )
}

async fn dashboard_script() -> Response<Body> {
    static_asset(
        "text/javascript; charset=utf-8",
        include_str!("../../frontend/Dashboard.js"),
    )
}

async fn admin_dashboard_styles() -> Response<Body> {
    static_asset(
        "text/css; charset=utf-8",
        include_str!("../../frontend/AdminDashboard.css"),
    )
}

async fn admin_dashboard_script() -> Response<Body> {
    static_asset(
        "text/javascript; charset=utf-8",
        include_str!("../../frontend/AdminDashboard.js"),
    )
}

fn static_asset(content_type: &'static str, content: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(content));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[utoipa::path(
    get, path = "/health", operation_id = "HealthCheck",
    summary = "Verificar disponibilidade da API", tag = "Eco Vision",
    responses((status = 200, description = "Serviço ativo"))
)]
async fn health() -> impl IntoResponse {
    Json(json!({"status":"ok","service":"eco-vision"}))
}

#[utoipa::path(
    post, path = "/api/v1/auth/register", operation_id = "RegisterCitizen",
    summary = "Criar conta de cidadão", tag = "Autenticação",
    request_body = AuthCredentials,
    responses((status = 201, description = "Conta criada e sessão iniciada", body = UserProfile), (status = 409, description = "E-mail já cadastrado", body = ApiError))
)]
async fn register(
    State(state): State<AppState>,
    Json(credentials): Json<AuthCredentials>,
) -> Result<Response<Body>, ApiFailure> {
    let grant = state
        .service
        .register_user(&credentials.email, &credentials.password)
        .await?;
    Ok(session_response(
        StatusCode::CREATED,
        &grant.token,
        state.service.cookie_secure(),
        grant.profile,
    ))
}

#[utoipa::path(
    post, path = "/api/v1/auth/login", operation_id = "Login",
    summary = "Iniciar sessão", tag = "Autenticação",
    request_body = LoginCredentials,
    responses((status = 200, description = "Sessão iniciada", body = UserProfile), (status = 401, description = "Credenciais inválidas, segundo fator inválido ou fator adicional necessário", body = ApiError), (status = 429, description = "Muitas tentativas de login; consulte Retry-After", body = ApiError), (status = 503, description = "Configuração de MFA indisponível", body = ApiError))
)]
async fn login(
    State(state): State<AppState>,
    client_ip: ClientIp,
    Json(credentials): Json<LoginCredentials>,
) -> Result<Response<Body>, ApiFailure> {
    let grant = state
        .service
        .login_user_with_second_factor(
            &credentials.email,
            &credentials.password,
            credentials.two_factor_code.as_deref(),
            client_ip.0,
        )
        .await?;
    Ok(session_response(
        StatusCode::OK,
        &grant.token,
        state.service.cookie_secure(),
        grant.profile,
    ))
}

#[utoipa::path(
    post, path = "/api/v1/auth/password", operation_id = "ChangePassword",
    summary = "Trocar senha e revogar sessões existentes", tag = "Autenticação",
    request_body = ChangePasswordRequest,
    responses((status = 200, description = "Senha alterada; todas as sessões foram encerradas"), (status = 401, description = "Credenciais inválidas", body = ApiError))
)]
async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Response<Body>, ApiFailure> {
    state
        .service
        .change_password(
            session_cookie(&headers),
            &request.current_password,
            &request.new_password,
            request.two_factor_code.as_deref(),
        )
        .await?;
    Ok(expired_session_response(
        json!({"message":"Senha alterada. Entre novamente."}),
        state.service.cookie_secure(),
    ))
}

#[utoipa::path(
    get, path = "/api/v1/auth/2fa/status", operation_id = "GetAdministratorTwoFactorStatus",
    summary = "Consultar o estado do segundo fator administrativo", tag = "Autenticação",
    params(("Cookie" = String, Header, description = "Cookie de sessão; exige perfil administrador")),
    responses((status = 200, description = "Estado do segundo fator", body = TwoFactorStatus), (status = 403, description = "Somente administradores", body = ApiError))
)]
async fn two_factor_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiFailure> {
    Ok(private_json(
        state
            .service
            .two_factor_status(session_cookie(&headers))
            .await?,
    ))
}

#[utoipa::path(
    post, path = "/api/v1/auth/2fa/setup", operation_id = "StartAdministratorTwoFactorSetup",
    summary = "Iniciar cadastro do aplicativo autenticador", tag = "Autenticação",
    params(("Cookie" = String, Header, description = "Cookie de sessão; exige perfil administrador")),
    request_body = TwoFactorSetupRequest,
    responses((status = 200, description = "Segredo e URI de cadastro; segredo mostrado uma vez", body = TwoFactorSetup), (status = 503, description = "Chave de cifragem MFA não configurada", body = ApiError))
)]
async fn start_two_factor_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TwoFactorSetupRequest>,
) -> Result<Response<Body>, ApiFailure> {
    Ok(private_json(
        state
            .service
            .start_two_factor_setup(session_cookie(&headers), &request.password)
            .await?,
    ))
}

#[utoipa::path(
    post, path = "/api/v1/auth/2fa/confirm", operation_id = "ConfirmAdministratorTwoFactorSetup",
    summary = "Confirmar configuração e gerar códigos de recuperação", tag = "Autenticação",
    params(("Cookie" = String, Header, description = "Cookie de sessão; exige perfil administrador")),
    request_body = TwoFactorCodeRequest,
    responses((status = 200, description = "Códigos de recuperação exibidos uma vez", body = RecoveryCodes), (status = 401, description = "Código TOTP inválido", body = ApiError))
)]
async fn confirm_two_factor_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TwoFactorCodeRequest>,
) -> Result<Response<Body>, ApiFailure> {
    Ok(private_json(
        state
            .service
            .confirm_two_factor_setup(session_cookie(&headers), &request.code)
            .await?,
    ))
}

#[utoipa::path(
    post, path = "/api/v1/auth/2fa/disable", operation_id = "DisableAdministratorTwoFactor",
    summary = "Desativar segundo fator com nova verificação", tag = "Autenticação",
    params(("Cookie" = String, Header, description = "Cookie de sessão; exige perfil administrador")),
    request_body = TwoFactorDisableRequest,
    responses((status = 200, description = "Segundo fator desativado e sessões revogadas"), (status = 401, description = "Credenciais inválidas", body = ApiError))
)]
async fn disable_two_factor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TwoFactorDisableRequest>,
) -> Result<Response<Body>, ApiFailure> {
    state
        .service
        .disable_two_factor(session_cookie(&headers), &request.password, &request.code)
        .await?;
    Ok(expired_session_response(
        json!({"message":"Segundo fator desativado. Entre novamente."}),
        state.service.cookie_secure(),
    ))
}

fn expired_session_response(body: serde_json::Value, secure: bool) -> Response<Body> {
    let mut response = private_json(body);
    let mut cookie = "eco_vision_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".to_owned();
    if secure {
        cookie.push_str("; Secure");
    }
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("static cookie attributes are valid"),
    );
    response
}

#[utoipa::path(
    get, path = "/api/v1/auth/me", operation_id = "GetCurrentAccount",
    summary = "Consultar conta da sessão atual", tag = "Autenticação",
    params(("Cookie" = String, Header, description = "Cookie de sessão eco_vision_session")),
    responses((status = 200, description = "Perfil autenticado", body = UserProfile), (status = 401, description = "Sessão ausente ou expirada", body = ApiError))
)]
async fn auth_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiFailure> {
    let profile = state.service.current_user(session_cookie(&headers)).await?;
    Ok(private_json(profile))
}

#[utoipa::path(
    post, path = "/api/v1/auth/logout", operation_id = "Logout",
    summary = "Encerrar sessão atual", tag = "Autenticação",
    params(("Cookie" = String, Header, description = "Cookie de sessão eco_vision_session")),
    responses((status = 200, description = "Sessão revogada"))
)]
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiFailure> {
    state.service.logout(session_cookie(&headers)).await?;
    let mut response = expired_session_response(
        json!({"message":"Sessão encerrada."}),
        state.service.cookie_secure(),
    );
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

fn session_response<T: serde::Serialize>(
    status: StatusCode,
    token: &str,
    secure: bool,
    body: T,
) -> Response<Body> {
    let mut response = private_json(body);
    *response.status_mut() = status;
    let mut cookie =
        format!("eco_vision_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200");
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

fn private_json<T: serde::Serialize>(body: T) -> Response<Body> {
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[utoipa::path(
    get, path = "/api/v1/dashboard", operation_id = "GetCitizenDashboard",
    summary = "Consultar painel de risco cidadão", tag = "Eco Vision",
    responses((status = 200, description = "Indicadores executivos agregados", body = Dashboard))
)]
async fn dashboard(State(state): State<AppState>) -> Result<Json<Dashboard>, ApiFailure> {
    state
        .service
        .dashboard()
        .await
        .map(Json)
        .map_err(Into::into)
}

#[utoipa::path(
    get, path = "/api/v1/privacy/status", operation_id = "GetPrivacyStatus",
    summary = "Consultar indicador público de privacidade e proteção de dados", tag = "Eco Vision",
    responses((status = 200, description = "Status de privacidade do sistema para cidadãos", body = CitizenPrivacyStatus))
)]
async fn privacy_status(
    State(state): State<AppState>,
) -> Result<Json<CitizenPrivacyStatus>, ApiFailure> {
    state
        .service
        .citizen_privacy_status()
        .await
        .map(Json)
        .map_err(Into::into)
}

#[utoipa::path(
    get, path = "/api/v1/reports", operation_id = "ListReports",
    summary = "Listar ocorrências resumidas", tag = "Eco Vision",
    responses((status = 200, description = "Lista resumida sem texto livre dos relatos", body = [ReportSummary]))
)]
async fn list_reports(
    State(state): State<AppState>,
) -> Result<Json<Vec<ReportSummary>>, ApiFailure> {
    state
        .service
        .list_reports()
        .await
        .map(Json)
        .map_err(Into::into)
}

#[utoipa::path(
    post, path = "/api/v1/reports", operation_id = "CreateReport",
    summary = "Registrar ocorrência com validação de PII", tag = "Eco Vision",
    request_body = CreateReport,
    responses(
        (status = 201, description = "Ocorrência registrada", body = ReportReceipt),
        (status = 422, description = "PII detectada ou campos inválidos; a resposta ao cidadão não revela as categorias", body = ApiError),
        (status = 401, description = "É necessário entrar na conta", body = ApiError),
        (status = 429, description = "Limite de envios atingido; consulte o cabeçalho Retry-After", body = ApiError)
    )
)]
async fn create_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    client_ip: ClientIp,
    Json(input): Json<CreateReport>,
) -> Result<(StatusCode, Json<ReportReceipt>), ApiFailure> {
    match state
        .service
        .create_report(session_cookie(&headers), client_ip.0, input)
        .await
    {
        Ok(receipt) => Ok((StatusCode::CREATED, Json(receipt))),
        Err(ApplicationError::PiiDetected) => Err(ApiFailure::citizen_pii()),
        Err(error) => Err(error.into()),
    }
}

struct ClientIp(IpAddr);

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(address)| address.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        Ok(Self(ip))
    }
}

#[utoipa::path(
    get, path = "/api/v1/weather", operation_id = "GetCityWeather",
    summary = "Consultar previsão meteorológica do território", tag = "Eco Vision",
    responses(
        (status = 200, description = "Condições meteorológicas consultadas na Open-Meteo", body = WeatherSummary),
        (status = 502, description = "Fonte externa indisponível", body = ApiError)
    )
)]
async fn weather(State(state): State<AppState>) -> Result<Json<WeatherSummary>, ApiFailure> {
    state.service.weather().await.map(Json).map_err(Into::into)
}

#[utoipa::path(
    get, path = "/api/v1/security/dashboard", operation_id = "GetSecurityDashboard",
    summary = "Consultar indicadores de segurança (administrador)", tag = "Eco Vision",
    params(("Cookie" = String, Header, description = "Cookie de sessão; exige perfil administrador")),
    responses(
        (status = 200, description = "Indicadores de PII, taint e bloqueios por limite", body = SecurityDashboard),
        (status = 401, description = "Sessão ausente ou expirada", body = ApiError),
        (status = 403, description = "A conta não tem perfil de administrador", body = ApiError)
    )
)]
async fn security_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiFailure> {
    let dashboard = state
        .service
        .security_dashboard(session_cookie(&headers))
        .await?;
    Ok(private_json(dashboard))
}

#[utoipa::path(
    post, path = "/api/v1/security/scan", operation_id = "ScanPersonalData",
    summary = "Demonstrar detecção de PII e política de taint (administrador)", tag = "Eco Vision",
    params(("Cookie" = String, Header, description = "Cookie de sessão; exige perfil administrador")),
    request_body = SecurityScanRequest,
    responses(
        (status = 200, description = "PII e taint avaliados; amostra descartada", body = SecurityScanResponse),
        (status = 401, description = "Sessão ausente ou expirada", body = ApiError),
        (status = 403, description = "A conta não tem perfil de administrador", body = ApiError)
    )
)]
async fn security_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SecurityScanRequest>,
) -> Result<Response<Body>, ApiFailure> {
    let scan = state
        .service
        .scan_security(session_cookie(&headers), request)
        .await?;
    Ok(private_json(scan))
}

#[utoipa::path(
    get, path = "/api/v1/security/audit", operation_id = "ListSecurityAuditEvents",
    summary = "Listar eventos de segurança minimizados", tag = "Eco Vision",
    params(("Cookie" = String, Header, description = "Cookie de sessão; exige perfil administrador")),
    responses(
        (status = 200, description = "Eventos sem payloads ou trechos de PII", body = [AuditSummary]),
        (status = 401, description = "Sessão ausente ou expirada", body = ApiError),
        (status = 403, description = "A conta não tem perfil de administrador", body = ApiError)
    )
)]
async fn security_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiFailure> {
    let audit = state
        .service
        .security_audit(session_cookie(&headers))
        .await?;
    Ok(private_json(audit))
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(str::trim)
                .find_map(|cookie| cookie.strip_prefix("eco_vision_session="))
        })
}

struct ApiFailure {
    status: StatusCode,
    body: ApiError,
    retry_after_seconds: Option<u64>,
}

impl From<ApplicationError> for ApiFailure {
    fn from(error: ApplicationError) -> Self {
        let (status, code, message, retry_after_seconds) = match error {
            ApplicationError::InvalidInput(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_INPUT",
                message,
                None,
            ),
            ApplicationError::PiiDetectedWithExplanation(message) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "PII_DETECTED",
                message,
                None,
            ),
            ApplicationError::PiiDetected => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "PII_DETECTED",
                "O relato não foi salvo porque pode conter dados pessoais.".to_owned(),
                None,
            ),
            ApplicationError::TaintBlocked => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "TAINT_BLOCKED",
                "A entrada não passou pela política de proteção de dados.".to_owned(),
                None,
            ),
            ApplicationError::Forbidden => (
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Seu perfil não tem permissão para esta operação.".to_owned(),
                None,
            ),
            ApplicationError::AuthenticationRequired | ApplicationError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Entre com seu e-mail e senha para continuar.".to_owned(),
                None,
            ),
            ApplicationError::InvalidTwoFactorCode => (
                StatusCode::UNAUTHORIZED,
                "INVALID_TWO_FACTOR_CODE",
                "Código de autenticação inválido. Confira o código ou use um código de recuperação.".to_owned(),
                None,
            ),
            ApplicationError::TwoFactorRequired => (
                StatusCode::UNAUTHORIZED,
                "TWO_FACTOR_REQUIRED",
                "Senha válida. Informe o código do autenticador ou um código de recuperação.".to_owned(),
                None,
            ),
            ApplicationError::EmailAlreadyRegistered => (
                StatusCode::CONFLICT,
                "EMAIL_ALREADY_REGISTERED",
                "Já existe uma conta com este e-mail.".to_owned(),
                None,
            ),
            ApplicationError::PasswordHashing => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Não foi possível concluir a autenticação.".to_owned(),
                None,
            ),
            ApplicationError::TwoFactorConfiguration => (
                StatusCode::SERVICE_UNAVAILABLE,
                "MFA_CONFIGURATION_REQUIRED",
                "O segundo fator está indisponível. Configure a chave de cifragem MFA no servidor.".to_owned(),
                None,
            ),
            ApplicationError::TwoFactorAlreadyEnabled => (
                StatusCode::CONFLICT,
                "MFA_ALREADY_ENABLED",
                "A autenticação em duas etapas já está ativa para esta conta.".to_owned(),
                None,
            ),
            ApplicationError::RateLimited { retry_after_seconds } => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "Limite de envios atingido. Aguarde antes de registrar outra ocorrência.".to_owned(),
                Some(retry_after_seconds),
            ),
            ApplicationError::LoginRateLimited { retry_after_seconds } => (
                StatusCode::TOO_MANY_REQUESTS,
                "LOGIN_RATE_LIMITED",
                "Muitas tentativas de acesso. Aguarde antes de tentar novamente.".to_owned(),
                Some(retry_after_seconds),
            ),
            ApplicationError::Database(error) => {
                tracing::error!("database error: {error}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Não foi possível concluir a operação.".to_owned(),
                    None,
                )
            }
            ApplicationError::WeatherUnavailable => (
                StatusCode::BAD_GATEWAY,
                "WEATHER_UNAVAILABLE",
                "A consulta meteorológica está indisponível no momento.".to_owned(),
                None,
            ),
        };
        Self {
            status,
            body: ApiError {
                code: code.to_owned(),
                message,
            },
            retry_after_seconds,
        }
    }
}

impl ApiFailure {
    fn citizen_pii() -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            body: ApiError {
                code: "PII_DETECTED".into(),
                message: "Não foi possível registrar. Remova informações pessoais do relato e tente novamente.".into(),
            },
            retry_after_seconds: None,
        }
    }
}

impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response<Body> {
        let mut response = (self.status, Json(self.body)).into_response();
        if let Some(seconds) = self.retry_after_seconds
            && let Ok(value) = seconds.to_string().parse()
        {
            response.headers_mut().insert("retry-after", value);
        }
        response
    }
}
