use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessRole {
    User,
    Administrator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    SubmitOccurrence,
    ViewSecurityDashboard,
    ViewSecurityAudit,
    RunPiiScan,
}

impl std::str::FromStr for AccessRole {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user" => Ok(Self::User),
            "administrator" => Ok(Self::Administrator),
            _ => Err(()),
        }
    }
}

pub fn role_allows(role: AccessRole, permission: Permission) -> bool {
    match role {
        AccessRole::User => permission == Permission::SubmitOccurrence,
        AccessRole::Administrator => true,
    }
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataOrigin {
    UserSupplied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataSink {
    PrivateDatabase,
    PublicDashboard,
    ExternalWeatherApi,
    LlmProvider,
    SystemLog,
    HttpResponse,
}

impl DataSink {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDatabase => "private_database",
            Self::PublicDashboard => "public_dashboard",
            Self::ExternalWeatherApi => "external_weather_api",
            Self::LlmProvider => "llm_provider",
            Self::SystemLog => "system_log",
            Self::HttpResponse => "http_response",
        }
    }
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct TaintDecision {
    pub origin: DataOrigin,
    pub sink: DataSink,
    pub allowed: bool,
    pub reason: String,
}

/// Encapsula o texto fornecido pelo usuário até que uma política permita explicitamente seu destino.
#[derive(Clone, Debug)]
pub struct TaintedText(String);

impl TaintedText {
    pub fn from_user(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str_for_inspection(&self) -> &str {
        &self.0
    }

    pub fn into_private_database(self, pii_scan_passed: bool) -> Result<String, TaintDecision> {
        let decision = decision_for_user_input(DataSink::PrivateDatabase, pii_scan_passed);
        if decision.allowed {
            Ok(self.0)
        } else {
            Err(decision)
        }
    }

    pub fn check_sink(&self, sink: DataSink, pii_scan_passed: bool) -> TaintDecision {
        decision_for_user_input(sink, pii_scan_passed)
    }
}

pub fn decision_for_user_input(sink: DataSink, pii_scan_passed: bool) -> TaintDecision {
    let (allowed, reason) = match sink {
        DataSink::PrivateDatabase if pii_scan_passed => (
            true,
            "Persistência privada permitida após validação de PII.".to_owned(),
        ),
        DataSink::PrivateDatabase => (
            false,
            "A entrada contém ou não passou pela verificação de dados pessoais.".to_owned(),
        ),
        DataSink::PublicDashboard => (
            false,
            "O painel público recebe apenas contagens e resumos estruturados, nunca texto livre original.".to_owned(),
        ),
        DataSink::ExternalWeatherApi => (
            false,
            "A consulta meteorológica usa apenas coordenadas do sistema, nunca texto do cidadão.".to_owned(),
        ),
        DataSink::LlmProvider => (
            false,
            "O provedor recebe apenas códigos técnicos fixos de eventos, nunca o texto do cidadão.".to_owned(),
        ),
        DataSink::SystemLog => (
            false,
            "Os logs do sistema nunca registram dados brutos fornecidos pelo cidadão ou credenciais.".to_owned(),
        ),
        DataSink::HttpResponse => (
            false,
            "Respostas públicas de erro ou confirmação nunca refletem dados sensíveis identificados.".to_owned(),
        ),
    };

    TaintDecision {
        origin: DataOrigin::UserSupplied,
        sink,
        allowed,
        reason,
    }
}

pub fn decisions_for_user_input(pii_scan_passed: bool) -> Vec<TaintDecision> {
    [
        DataSink::PrivateDatabase,
        DataSink::PublicDashboard,
        DataSink::ExternalWeatherApi,
        DataSink::LlmProvider,
        DataSink::SystemLog,
        DataSink::HttpResponse,
    ]
    .into_iter()
    .map(|sink| decision_for_user_input(sink, pii_scan_passed))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_text_requires_a_clean_scan_before_private_persistence() {
        let tainted = TaintedText::from_user("relato comunitário");
        assert!(tainted.into_private_database(false).is_err());

        let tainted = TaintedText::from_user("relato comunitário");
        assert_eq!(
            tainted.into_private_database(true).unwrap(),
            "relato comunitário"
        );
    }

    #[test]
    fn user_text_is_never_authorized_for_external_sinks() {
        let decisions = decisions_for_user_input(true);
        for sink in [
            DataSink::PublicDashboard,
            DataSink::ExternalWeatherApi,
            DataSink::LlmProvider,
            DataSink::SystemLog,
            DataSink::HttpResponse,
        ] {
            assert!(
                !decisions
                    .iter()
                    .find(|decision| decision.sink == sink)
                    .unwrap()
                    .allowed
            );
        }
    }

    #[test]
    fn tainted_text_can_check_individual_sinks() {
        let tainted = TaintedText::from_user("dados sensiveis");
        let log_decision = tainted.check_sink(DataSink::SystemLog, true);
        assert!(!log_decision.allowed);

        let http_decision = tainted.check_sink(DataSink::HttpResponse, true);
        assert!(!http_decision.allowed);
    }

    #[test]
    fn user_and_administrator_roles_have_separate_permissions() {
        assert!(role_allows(AccessRole::User, Permission::SubmitOccurrence));
        assert!(!role_allows(
            AccessRole::User,
            Permission::ViewSecurityDashboard
        ));
        assert!(!role_allows(
            AccessRole::User,
            Permission::ViewSecurityAudit
        ));
        assert!(!role_allows(AccessRole::User, Permission::RunPiiScan));
        assert!(role_allows(
            AccessRole::Administrator,
            Permission::ViewSecurityDashboard
        ));
        assert!(role_allows(
            AccessRole::Administrator,
            Permission::ViewSecurityAudit
        ));
    }
}
