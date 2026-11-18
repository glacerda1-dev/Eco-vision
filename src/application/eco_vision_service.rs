use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    contracts::api_contracts::{
        AuditSummary, CitizenPrivacyStatus, CreateReport, Dashboard, RecoveryCodes, ReportReceipt,
        ReportSummary, SecurityDashboard, SecurityScanRequest, SecurityScanResponse,
        TwoFactorSetup, TwoFactorStatus, UserProfile, WeatherSummary,
    },
    domain::{
        pii_detector::{PiiFinding, scan_json_pii, scan_pii},
        risk_scoring::{citizen_risk_score, risk_level},
    },
    infrastructure::{
        app_configuration::Config,
        database_repository::{DatabaseRepository, SessionAccount, StoredAccount},
        llm_alert_translator::{
            SecurityEventCode, translate_security_alert, translate_security_code,
        },
        weather_provider::fetch_city_weather,
    },
    security::{
        passwords::{hash_password, verify_password},
        rate_limiter::{LoginAttemptLimiter, RateLimitResult, ReportRateLimiter},
        taint_policy::{
            AccessRole, DataSink, Permission, TaintedText, decisions_for_user_input, role_allows,
        },
        two_factor::{
            create_recovery_codes, decrypt_secret, encrypt_secret, hash_recovery_code,
            new_totp_setup, verify_totp,
        },
    },
};

const SESSION_LIFETIME_SECONDS: i64 = 12 * 60 * 60;

#[derive(Debug)]
pub enum ApplicationError {
    InvalidInput(String),
    PiiDetected,
    PiiDetectedWithExplanation(String),
    TaintBlocked,
    Database(sqlx::Error),
    WeatherUnavailable,
    Forbidden,
    AuthenticationRequired,
    InvalidCredentials,
    InvalidTwoFactorCode,
    TwoFactorRequired,
    EmailAlreadyRegistered,
    PasswordHashing,
    RateLimited { retry_after_seconds: u64 },
    LoginRateLimited { retry_after_seconds: u64 },
    TwoFactorConfiguration,
    TwoFactorAlreadyEnabled,
}

impl std::fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ApplicationError {}

#[derive(Debug)]
pub struct SessionGrant {
    pub token: String,
    pub profile: UserProfile,
}

#[derive(Clone)]
pub struct EcoVisionService {
    repository: DatabaseRepository,
    config: Config,
    report_rate_limiter: ReportRateLimiter,
    login_attempt_limiter: LoginAttemptLimiter,
    dummy_password_hash: String,
    http_client: reqwest::Client,
}

impl EcoVisionService {
    pub fn new(repository: DatabaseRepository, config: Config) -> Result<Self, ApplicationError> {
        let dummy_password = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
        let dummy_password_hash =
            hash_password(&dummy_password).map_err(|_| ApplicationError::PasswordHashing)?;
        Ok(Self {
            repository,
            config,
            report_rate_limiter: ReportRateLimiter::default(),
            login_attempt_limiter: LoginAttemptLimiter::default(),
            dummy_password_hash,
            http_client: reqwest::Client::new(),
        })
    }

    pub fn cookie_secure(&self) -> bool {
        self.config.cookie_secure
    }

    /// Provisiona a conta de administrador a partir de credenciais passadas diretamente.
    /// Deve ser chamado uma única vez durante a inicialização; as strings são descartadas
    /// pelo chamador logo após o retorno.
    pub async fn bootstrap_administrator(
        &self,
        admin_email: Option<&str>,
        admin_password: Option<&str>,
    ) -> Result<(), ApplicationError> {
        match (admin_email, admin_password) {
            (None, None) => Ok(()),
            (Some(email), Some(password)) => {
                let email = normalize_email(email)?;
                validate_password(password)?;
                let password_hash = hash_password_async(password.to_owned()).await?;
                self.repository
                    .bootstrap_administrator(&Uuid::new_v4().to_string(), &email, &password_hash)
                    .await
                    .map_err(ApplicationError::Database)
            }
            _ => Err(ApplicationError::InvalidInput(
                "Configure o e-mail e a senha do administrador juntos no ambiente.".into(),
            )),
        }
    }

    pub async fn register_user(
        &self,
        email: &str,
        password: &str,
    ) -> Result<SessionGrant, ApplicationError> {
        let email = normalize_email(email)?;
        validate_password(password)?;
        let password_hash = hash_password_async(password.to_owned()).await?;
        let user_id = Uuid::new_v4().to_string();
        let created = self
            .repository
            .create_citizen_account(&user_id, &email, &password_hash)
            .await
            .map_err(ApplicationError::Database)?;
        if !created {
            return Err(ApplicationError::EmailAlreadyRegistered);
        }

        self.issue_session(StoredAccount {
            id: user_id,
            email,
            password_hash,
            role: AccessRole::User,
            two_factor_secret_encrypted: None,
            two_factor_enabled: false,
        })
        .await
    }

    pub async fn login_user(
        &self,
        email: &str,
        password: &str,
    ) -> Result<SessionGrant, ApplicationError> {
        self.login_user_with_second_factor(
            email,
            password,
            None,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        )
        .await
    }

    pub async fn login_user_with_second_factor(
        &self,
        email: &str,
        password: &str,
        two_factor_code: Option<&str>,
        client_ip: IpAddr,
    ) -> Result<SessionGrant, ApplicationError> {
        if let Some(retry_after_seconds) = self.login_attempt_limiter.retry_after(client_ip) {
            return Err(ApplicationError::LoginRateLimited {
                retry_after_seconds,
            });
        }
        let normalized_email =
            normalize_email(email).unwrap_or_else(|_| email.trim().to_lowercase());
        let account = self
            .repository
            .find_account_by_email(&normalized_email)
            .await
            .map_err(ApplicationError::Database)?;
        let hash_to_verify = account
            .as_ref()
            .map(|account| account.password_hash.clone())
            .unwrap_or_else(|| self.dummy_password_hash.clone());
        let candidate = password.to_owned();
        let password_matches = verify_password_async(candidate, hash_to_verify).await?;

        let Some(account) = account.filter(|_| password_matches) else {
            self.login_attempt_limiter.record_failure(client_ip);
            return Err(ApplicationError::InvalidCredentials);
        };
        if account.role == AccessRole::Administrator
            && account.two_factor_enabled
            && let Err(error) = self
                .verify_admin_second_factor(&account, two_factor_code)
                .await
        {
            if matches!(error, ApplicationError::InvalidTwoFactorCode) {
                self.login_attempt_limiter.record_failure(client_ip);
            }
            return Err(error);
        }
        self.login_attempt_limiter.clear(client_ip);
        self.issue_session(account).await
    }

    pub async fn two_factor_status(
        &self,
        session_token: Option<&str>,
    ) -> Result<TwoFactorStatus, ApplicationError> {
        let account = self
            .require_permission(session_token, Permission::ViewSecurityDashboard)
            .await?;
        Ok(TwoFactorStatus {
            enabled: self
                .repository
                .two_factor_enabled(&account.id)
                .await
                .map_err(ApplicationError::Database)?,
        })
    }

    pub async fn start_two_factor_setup(
        &self,
        session_token: Option<&str>,
        password: &str,
    ) -> Result<TwoFactorSetup, ApplicationError> {
        let session = self
            .require_permission(session_token, Permission::ViewSecurityDashboard)
            .await?;
        let account = self.account_for_session(&session).await?;
        let password_matches =
            verify_password_async(password.to_owned(), account.password_hash.clone()).await?;
        if !password_matches {
            return Err(ApplicationError::InvalidCredentials);
        }
        if account.two_factor_enabled {
            return Err(ApplicationError::TwoFactorAlreadyEnabled);
        }
        let key = self
            .config
            .mfa_encryption_key
            .as_deref()
            .ok_or(ApplicationError::TwoFactorConfiguration)?;
        let (secret, otpauth_uri) =
            new_totp_setup(&account.email).map_err(|_| ApplicationError::TwoFactorConfiguration)?;
        let encrypted =
            encrypt_secret(&secret, key).map_err(|_| ApplicationError::TwoFactorConfiguration)?;
        let saved = self
            .repository
            .save_pending_two_factor_secret(&account.id, &encrypted)
            .await
            .map_err(ApplicationError::Database)?;
        if !saved {
            return Err(ApplicationError::TwoFactorAlreadyEnabled);
        }
        Ok(TwoFactorSetup {
            secret,
            otpauth_uri,
        })
    }

    pub async fn confirm_two_factor_setup(
        &self,
        session_token: Option<&str>,
        code: &str,
    ) -> Result<RecoveryCodes, ApplicationError> {
        let session = self
            .require_permission(session_token, Permission::ViewSecurityDashboard)
            .await?;
        let account = self.account_for_session(&session).await?;
        if account.two_factor_enabled {
            return Err(ApplicationError::TwoFactorAlreadyEnabled);
        }
        let key = self
            .config
            .mfa_encryption_key
            .as_deref()
            .ok_or(ApplicationError::TwoFactorConfiguration)?;
        let encrypted = self
            .repository
            .pending_two_factor_secret(&account.id)
            .await
            .map_err(ApplicationError::Database)?
            .ok_or(ApplicationError::InvalidCredentials)?;
        let secret = decrypt_secret(&encrypted, key)
            .map_err(|_| ApplicationError::TwoFactorConfiguration)?;
        if !verify_totp(&account.email, &secret, code) {
            return Err(ApplicationError::InvalidTwoFactorCode);
        }

        let codes = create_recovery_codes();
        let hashes: Vec<String> = codes.iter().map(|code| hash_recovery_code(code)).collect();
        let enabled = self
            .repository
            .enable_two_factor(&account.id, &hashes)
            .await
            .map_err(ApplicationError::Database)?;
        if !enabled {
            return Err(ApplicationError::InvalidCredentials);
        }
        Ok(RecoveryCodes { codes })
    }

    pub async fn disable_two_factor(
        &self,
        session_token: Option<&str>,
        password: &str,
        code: &str,
    ) -> Result<(), ApplicationError> {
        let session = self
            .require_permission(session_token, Permission::ViewSecurityDashboard)
            .await?;
        let account = self.account_for_session(&session).await?;
        if !account.two_factor_enabled {
            return Err(ApplicationError::InvalidCredentials);
        }
        if !verify_password_async(password.to_owned(), account.password_hash.clone()).await? {
            return Err(ApplicationError::InvalidCredentials);
        }
        self.verify_admin_second_factor(&account, Some(code))
            .await?;
        self.repository
            .disable_two_factor_and_revoke_sessions(&account.id)
            .await
            .map_err(ApplicationError::Database)
    }

    pub async fn change_password(
        &self,
        session_token: Option<&str>,
        current_password: &str,
        new_password: &str,
        two_factor_code: Option<&str>,
    ) -> Result<(), ApplicationError> {
        let session = self.require_session(session_token).await?;
        let account = self.account_for_session(&session).await?;
        if !verify_password_async(current_password.to_owned(), account.password_hash.clone())
            .await?
        {
            return Err(ApplicationError::InvalidCredentials);
        }
        if account.role == AccessRole::Administrator && account.two_factor_enabled {
            self.verify_admin_second_factor(&account, two_factor_code)
                .await?;
        }
        validate_password(new_password)?;
        if current_password == new_password {
            return Err(ApplicationError::InvalidInput(
                "Escolha uma senha diferente da atual.".into(),
            ));
        }
        let password_hash = hash_password_async(new_password.to_owned()).await?;
        self.repository
            .update_password_and_revoke_sessions(&account.id, &password_hash)
            .await
            .map_err(ApplicationError::Database)
    }

    async fn verify_admin_second_factor(
        &self,
        account: &StoredAccount,
        code: Option<&str>,
    ) -> Result<(), ApplicationError> {
        let Some(code) = code.filter(|value| !value.trim().is_empty()) else {
            return Err(ApplicationError::TwoFactorRequired);
        };
        let normalized_code = code.trim();
        let is_totp_code = normalized_code.len() == 6
            && normalized_code
                .bytes()
                .all(|character| character.is_ascii_digit());
        if !is_totp_code {
            let consumed = self
                .repository
                .consume_recovery_code(&account.id, &hash_recovery_code(normalized_code))
                .await
                .map_err(ApplicationError::Database)?;
            return if consumed {
                Ok(())
            } else {
                Err(ApplicationError::InvalidTwoFactorCode)
            };
        }
        let key = self
            .config
            .mfa_encryption_key
            .as_deref()
            .ok_or(ApplicationError::TwoFactorConfiguration)?;
        let encrypted = account
            .two_factor_secret_encrypted
            .as_deref()
            .ok_or(ApplicationError::TwoFactorConfiguration)?;
        let secret =
            decrypt_secret(encrypted, key).map_err(|_| ApplicationError::TwoFactorConfiguration)?;
        if verify_totp(&account.email, &secret, normalized_code) {
            return Ok(());
        }
        Err(ApplicationError::InvalidTwoFactorCode)
    }

    async fn account_for_session(
        &self,
        session: &SessionAccount,
    ) -> Result<StoredAccount, ApplicationError> {
        self.repository
            .find_account_by_id(&session.id)
            .await
            .map_err(ApplicationError::Database)?
            .ok_or(ApplicationError::AuthenticationRequired)
    }

    async fn issue_session(
        &self,
        account: StoredAccount,
    ) -> Result<SessionGrant, ApplicationError> {
        // Two independently generated UUIDs provide a high-entropy bearer value.
        let token = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
        let expires_at = now_epoch() + SESSION_LIFETIME_SECONDS;
        self.repository
            .create_session(&hash_session_token(&token), &account.id, expires_at)
            .await
            .map_err(ApplicationError::Database)?;
        Ok(SessionGrant {
            token,
            profile: UserProfile {
                email: account.email,
                role: account.role,
            },
        })
    }

    pub async fn current_user(
        &self,
        session_token: Option<&str>,
    ) -> Result<UserProfile, ApplicationError> {
        Ok(self.require_session(session_token).await?.profile)
    }

    pub async fn logout(&self, session_token: Option<&str>) -> Result<(), ApplicationError> {
        if let Some(token) = session_token.filter(|token| !token.is_empty()) {
            self.repository
                .delete_session(&hash_session_token(token))
                .await
                .map_err(ApplicationError::Database)?;
        }
        Ok(())
    }

    pub async fn dashboard(&self) -> Result<Dashboard, ApplicationError> {
        let counts = self
            .repository
            .dashboard_counts()
            .await
            .map_err(ApplicationError::Database)?;
        let privacy = self
            .repository
            .citizen_privacy_status()
            .await
            .map_err(ApplicationError::Database)?;
        let score = citizen_risk_score(counts.open_reports, counts.high_severity_reports);
        Ok(Dashboard {
            city: self.config.demo_city.clone(),
            risk_score: score,
            risk_level: risk_level(score).into(),
            open_reports: counts.open_reports,
            high_severity_reports: counts.high_severity_reports,
            resolved_reports: counts.resolved_reports,
            data_label: "Contém registros demonstrativos.".into(),
            privacy,
        })
    }

    pub async fn citizen_privacy_status(&self) -> Result<CitizenPrivacyStatus, ApplicationError> {
        self.repository
            .citizen_privacy_status()
            .await
            .map_err(ApplicationError::Database)
    }

    pub async fn security_dashboard(
        &self,
        session_token: Option<&str>,
    ) -> Result<SecurityDashboard, ApplicationError> {
        self.require_permission(session_token, Permission::ViewSecurityDashboard)
            .await?;
        let counts = self
            .repository
            .security_counts()
            .await
            .map_err(ApplicationError::Database)?;
        Ok(SecurityDashboard {
            blocked_pii_submissions: counts.blocked_pii_submissions,
            outbound_taint_blocks: counts.outbound_taint_blocks,
            rate_limited_submissions: self.report_rate_limiter.blocked_request_count(),
            max_reports_per_window: ReportRateLimiter::max_requests_per_window() as u32,
            window_seconds: ReportRateLimiter::window_seconds(),
        })
    }

    pub async fn list_reports(&self) -> Result<Vec<ReportSummary>, ApplicationError> {
        self.repository
            .list_reports()
            .await
            .map_err(ApplicationError::Database)
    }

    pub async fn create_report(
        &self,
        session_token: Option<&str>,
        client_ip: IpAddr,
        input: CreateReport,
    ) -> Result<ReportReceipt, ApplicationError> {
        let account = self
            .require_permission(session_token, Permission::SubmitOccurrence)
            .await?;
        if let RateLimitResult::Limited {
            retry_after_seconds,
            record_security_event,
        } = self.report_rate_limiter.check(client_ip)
        {
            if record_security_event {
                self.repository
                    .record_security_event(
                        "report_rate_limited",
                        &[],
                        "occurrence_submission_rejected_by_per_ip_rate_limit",
                        DataSink::HttpResponse.as_str(),
                        "blocked",
                        "Limite de envios por IP excedido",
                    )
                    .await
                    .map_err(ApplicationError::Database)?;
            }
            return Err(ApplicationError::RateLimited {
                retry_after_seconds,
            });
        }

        let category = TaintedText::from_user(&input.category);
        let details = TaintedText::from_user(&input.details);
        let neighborhood = TaintedText::from_user(&input.neighborhood);
        if category.as_str_for_inspection().trim().is_empty()
            || neighborhood.as_str_for_inspection().trim().is_empty()
            || category.as_str_for_inspection().chars().count() > 80
            || details.as_str_for_inspection().chars().count() > 1500
            || neighborhood.as_str_for_inspection().chars().count() > 100
        {
            return Err(ApplicationError::InvalidInput(
                "Informe categoria e bairro. O relato é opcional. Limites: 80, 1.500 e 100 caracteres.".into(),
            ));
        }

        let json_input = serde_json::json!({
            "category": input.category,
            "details": input.details,
            "neighborhood": input.neighborhood,
        });
        let findings = scan_json_pii(&json_input);
        if !findings.is_empty() {
            let finding_names = finding_names(&findings);
            self.repository
                .record_security_event(
                    "report_blocked_pii",
                    &finding_names,
                    "blocked_user_input_from_private_database_and_all_sinks",
                    DataSink::PrivateDatabase.as_str(),
                    "blocked",
                    "Entrada bloqueada preventivamente: presença de dados pessoais",
                )
                .await
                .map_err(ApplicationError::Database)?;

            let translation = translate_security_code(
                &self.http_client,
                &self.config,
                SecurityEventCode::PiiDetected,
            )
            .await;

            return Err(ApplicationError::PiiDetectedWithExplanation(
                translation.message,
            ));
        }

        let category_clean = category
            .into_private_database(true)
            .map_err(|_| ApplicationError::TaintBlocked)?;
        let details_clean = details
            .into_private_database(true)
            .map_err(|_| ApplicationError::TaintBlocked)?;
        let neighborhood_clean = neighborhood
            .into_private_database(true)
            .map_err(|_| ApplicationError::TaintBlocked)?;
        let id = Uuid::new_v4().to_string();

        self.repository
            .insert_report(
                &id,
                &account.id,
                category_clean.trim(),
                details_clean.trim(),
                neighborhood_clean.trim(),
                input.severity,
            )
            .await
            .map_err(ApplicationError::Database)?;
        self.repository
            .record_security_event(
                "report_accepted",
                &[],
                "authorized_for_private_persistence; blocked_from_public_dashboard_external_api_and_llm",
                DataSink::PrivateDatabase.as_str(),
                "allowed",
                "Persistência privada autorizada após triagem limpa de PII",
            )
            .await
            .map_err(ApplicationError::Database)?;

        Ok(ReportReceipt {
            id,
            status: "open".into(),
            privacy: "texto livre privado; painel mostra somente resumo".into(),
            message: "Ocorrência registrada. Obrigado por contribuir com sua comunidade.".into(),
        })
    }

    pub async fn weather(&self) -> Result<WeatherSummary, ApplicationError> {
        fetch_city_weather(&self.http_client, &self.config)
            .await
            .map_err(|_| ApplicationError::WeatherUnavailable)
    }

    pub async fn scan_security(
        &self,
        session_token: Option<&str>,
        request: SecurityScanRequest,
    ) -> Result<SecurityScanResponse, ApplicationError> {
        self.require_permission(session_token, Permission::RunPiiScan)
            .await?;
        if request.sample.chars().count() > 3000 {
            return Err(ApplicationError::InvalidInput(
                "A amostra deve ter até 3.000 caracteres.".into(),
            ));
        }
        let sample = TaintedText::from_user(request.sample);
        let findings = scan_pii(sample.as_str_for_inspection());
        let finding_names = finding_names(&findings);
        let accepted = findings.is_empty();
        let translation =
            translate_security_alert(&self.http_client, &self.config, !accepted).await;
        self.repository
            .record_security_event(
                if accepted {
                    "pii_scan_clean"
                } else {
                    "pii_scan_blocked"
                },
                &finding_names,
                if accepted {
                    "sample_clean_no_pii_detected"
                } else {
                    "sample_blocked_pii_detected"
                },
                DataSink::SystemLog.as_str(),
                if accepted { "allowed" } else { "blocked" },
                if accepted {
                    "Verificação de amostra limpa sem PII"
                } else {
                    "Amostra de teste continha dados pessoais"
                },
            )
            .await
            .map_err(ApplicationError::Database)?;

        Ok(SecurityScanResponse {
            accepted,
            findings: finding_names,
            taint_decisions: decisions_for_user_input(accepted),
            citizen_message: translation.message,
            translation_source: translation.source,
        })
    }

    pub async fn security_audit(
        &self,
        session_token: Option<&str>,
    ) -> Result<Vec<AuditSummary>, ApplicationError> {
        self.require_permission(session_token, Permission::ViewSecurityAudit)
            .await?;
        self.repository
            .list_security_events()
            .await
            .map_err(ApplicationError::Database)
    }

    async fn require_permission(
        &self,
        session_token: Option<&str>,
        permission: Permission,
    ) -> Result<SessionAccount, ApplicationError> {
        let account = self.require_session(session_token).await?;
        if role_allows(account.profile.role, permission) {
            Ok(account)
        } else {
            Err(ApplicationError::Forbidden)
        }
    }

    async fn require_session(
        &self,
        session_token: Option<&str>,
    ) -> Result<SessionAccount, ApplicationError> {
        let token = session_token
            .filter(|token| !token.is_empty())
            .ok_or(ApplicationError::AuthenticationRequired)?;
        self.repository
            .session_account(&hash_session_token(token), now_epoch())
            .await
            .map_err(ApplicationError::Database)?
            .ok_or(ApplicationError::AuthenticationRequired)
    }
}

async fn hash_password_async(password: String) -> Result<String, ApplicationError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| ApplicationError::PasswordHashing)?
        .map_err(|_| ApplicationError::PasswordHashing)
}

async fn verify_password_async(
    password: String,
    encoded_hash: String,
) -> Result<bool, ApplicationError> {
    tokio::task::spawn_blocking(move || verify_password(&password, &encoded_hash))
        .await
        .map_err(|_| ApplicationError::PasswordHashing)
}

fn normalize_email(email: &str) -> Result<String, ApplicationError> {
    let email = email.trim().to_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return Err(ApplicationError::InvalidInput(
            "Informe um e-mail válido.".into(),
        ));
    };
    if email.len() > 254
        || local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || email.chars().any(char::is_whitespace)
    {
        return Err(ApplicationError::InvalidInput(
            "Informe um e-mail válido.".into(),
        ));
    }
    Ok(email)
}

fn validate_password(password: &str) -> Result<(), ApplicationError> {
    let characters = password.chars().count();
    if !(12..=128).contains(&characters) || password.len() > 512 {
        return Err(ApplicationError::InvalidInput(
            "Use uma senha entre 12 e 128 caracteres.".into(),
        ));
    }
    Ok(())
}

fn hash_session_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn finding_names(findings: &[PiiFinding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| finding.kind.as_str().to_owned())
        .collect()
}
