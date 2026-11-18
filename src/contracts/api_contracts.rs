use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::security::taint_policy::AccessRole;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateReport {
    /// Tipo curto da ocorrência, por exemplo "alagamento" ou "bueiro obstruído".
    pub category: String,
    /// Relato para a equipe responsável; não informe nome, telefone, CPF ou senha.
    pub details: String,
    /// Bairro ou região ampla, sem endereço residencial.
    pub neighborhood: String,
    pub severity: Severity,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportReceipt {
    pub id: String,
    pub status: String,
    pub privacy: String,
    pub message: String,
}

/// Projeção pública deliberadamente limitada: não inclui o texto livre do relato.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReportSummary {
    pub id: String,
    pub category: String,
    pub neighborhood: String,
    pub severity: Severity,
    pub status: String,
    pub created_at: String,
    pub demonstrative: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Dashboard {
    pub city: String,
    pub risk_score: u8,
    pub risk_level: String,
    pub open_reports: i64,
    pub high_severity_reports: i64,
    pub resolved_reports: i64,
    pub data_label: String,
    pub privacy: CitizenPrivacyStatus,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CitizenPrivacyStatus {
    /// Nível visual determinístico: "green" (normal), "yellow" (prevenção acionada), "red" (crítico/atenção)
    pub status: String,
    pub status_label: String,
    pub message: String,
    pub blocked_preventions_count: i64,
    pub last_event_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityDashboard {
    pub blocked_pii_submissions: i64,
    pub outbound_taint_blocks: i64,
    /// Requests rejected by the in-memory limiter since this process started.
    pub rate_limited_submissions: u64,
    pub max_reports_per_window: u32,
    pub window_seconds: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthCredentials {
    /// Endereço de e-mail usado para entrar na conta.
    pub email: String,
    /// A senha é enviada somente por HTTPS em implantação pública.
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginCredentials {
    /// Endereço de e-mail usado para entrar na conta.
    pub email: String,
    /// Senha da conta.
    pub password: String,
    /// Código TOTP atual ou código de recuperação, obrigatório para admin com 2FA ativo.
    #[serde(default)]
    pub two_factor_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TwoFactorSetupRequest {
    /// Confirmação da senha atual antes de iniciar o cadastro do autenticador.
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TwoFactorCodeRequest {
    /// Código de seis dígitos do aplicativo autenticador.
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TwoFactorDisableRequest {
    pub password: String,
    /// Código atual do autenticador ou código de recuperação ainda não usado.
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    /// Obrigatório para administradores com 2FA ativo; aceita TOTP ou recuperação.
    #[serde(default)]
    pub two_factor_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TwoFactorStatus {
    pub enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TwoFactorSetup {
    /// Segredo exibido uma única vez para cadastro manual no autenticador.
    pub secret: String,
    /// URI otpauth compatível com aplicativos autenticadores.
    pub otpauth_uri: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryCodes {
    /// Exibidos uma única vez; cada código só pode ser usado em um login.
    pub codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct UserProfile {
    pub email: String,
    pub role: AccessRole,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SecurityScanRequest {
    /// Texto sintético para demonstração; a entrada não é armazenada nem enviada ao LLM.
    pub sample: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityScanResponse {
    pub accepted: bool,
    pub findings: Vec<String>,
    pub taint_decisions: Vec<crate::security::taint_policy::TaintDecision>,
    pub citizen_message: String,
    pub translation_source: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditSummary {
    pub event_type: String,
    pub finding_kinds: Vec<String>,
    pub taint_decision: String,
    pub sink: String,
    pub decision: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WeatherSummary {
    pub city: String,
    pub precipitation_mm: f64,
    pub forecast_probability_percent: Option<u8>,
    pub risk_level: String,
    pub source: String,
    pub observed_at: Option<DateTime<Utc>>,
}
