use serde::Deserialize;

use crate::infrastructure::app_configuration::Config;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityEventCode {
    PiiDetected,
    TaintSinkBlocked,
    UnsafeLogBlocked,
    HttpOutputBlocked,
    UnauthorizedSecurityAccess,
    RateLimitTriggered,
    SecurityValidationFailed,
    NoKnownPii,
}

impl SecurityEventCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PiiDetected => "PII_DETECTED",
            Self::TaintSinkBlocked => "TAINT_SINK_BLOCKED",
            Self::UnsafeLogBlocked => "UNSAFE_LOG_BLOCKED",
            Self::HttpOutputBlocked => "HTTP_OUTPUT_BLOCKED",
            Self::UnauthorizedSecurityAccess => "UNAUTHORIZED_SECURITY_ACCESS",
            Self::RateLimitTriggered => "RATE_LIMIT_TRIGGERED",
            Self::SecurityValidationFailed => "SECURITY_VALIDATION_FAILED",
            Self::NoKnownPii => "NO_KNOWN_PII",
        }
    }

    pub fn default_fallback_message(&self) -> &'static str {
        match self {
            Self::PiiDetected => {
                "Identificamos informações pessoais no seu relato e impedimos o envio para proteger sua privacidade. Remova esses dados e tente novamente."
            }
            Self::TaintSinkBlocked => {
                "A política de proteção de dados bloqueou o compartilhamento da informação com um canal externo não autorizado."
            }
            Self::UnsafeLogBlocked => {
                "O registro de informações sensíveis nos logs do sistema foi bloqueado por motivos de segurança e privacidade."
            }
            Self::HttpOutputBlocked => {
                "O envio de dados pessoais em respostas públicas foi bloqueado para resguardar a privacidade comunitária."
            }
            Self::UnauthorizedSecurityAccess => {
                "A tentativa de acessar funções de segurança sem permissão administrativa foi recusada."
            }
            Self::RateLimitTriggered => {
                "Muitas solicitações foram enviadas em pouco tempo. O limite de segurança foi acionado para proteger o serviço."
            }
            Self::SecurityValidationFailed => {
                "A validação de segurança encontrou inconformidades nos dados enviados e interrompeu o processamento."
            }
            Self::NoKnownPii => {
                "Não encontramos dados pessoais conhecidos no exemplo. Ainda assim, lembre-se de nunca incluir dados que identifiquem alguém."
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct CitizenTranslation {
    pub message: String,
    pub source: String,
}

#[derive(Deserialize)]
struct ChatCompletion {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

/// O provedor LLM recebe EXCLUSIVAMENTE um código fixo e autorizado de evento técnico.
/// Jamais recebe o texto digitado pelo cidadão, documentos, emails ou dados pessoais.
pub async fn translate_security_code(
    client: &reqwest::Client,
    config: &Config,
    event_code: SecurityEventCode,
) -> CitizenTranslation {
    let fallback = event_code.default_fallback_message();
    let (Some(url), Some(key)) = (&config.llm_api_url, &config.llm_api_key) else {
        return CitizenTranslation {
            message: fallback.to_owned(),
            source: "mensagem local de segurança".into(),
        };
    };

    let code_str = event_code.as_str();
    let body = serde_json::json!({
        "model": config.llm_model,
        "messages": [
            {
                "role": "system",
                "content": "Você é um assistente de privacidade e segurança da plataforma comunitária Eco Vision. Traduza o código de segurança técnico em uma frase simples, acolhedora, respeitosa e clara em português do Brasil para um cidadão comum. Não invente incidentes ou dados. Máximo de 2 frases."
            },
            {
                "role": "user",
                "content": format!("Código técnico: {code_str}")
            }
        ],
        "temperature": 0.1,
        "max_tokens": 120
    });

    let response = client
        .post(url)
        .bearer_auth(key)
        .json(&body)
        .timeout(std::time::Duration::from_secs(4))
        .send()
        .await;

    if let Ok(response) = response
        && let Ok(response) = response.error_for_status()
        && let Ok(completion) = response.json::<ChatCompletion>().await
        && let Some(message) = completion
            .choices
            .first()
            .map(|choice| choice.message.content.trim())
            .filter(|s| !s.is_empty() && s.len() <= 280)
    {
        return CitizenTranslation {
            message: message.to_owned(),
            source: "provedor LLM".into(),
        };
    }

    CitizenTranslation {
        message: fallback.to_owned(),
        source: "mensagem local de segurança (LLM indisponível)".into(),
    }
}

/// Mantém retrocompatibilidade para chamadas que passam apenas `has_pii: bool`
pub async fn translate_security_alert(
    client: &reqwest::Client,
    config: &Config,
    has_pii: bool,
) -> CitizenTranslation {
    let code = if has_pii {
        SecurityEventCode::PiiDetected
    } else {
        SecurityEventCode::NoKnownPii
    };
    translate_security_code(client, config, code).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn translates_with_local_fallback_when_llm_not_configured() {
        let client = reqwest::Client::new();
        let config = Config {
            database_url: "sqlite::memory:".into(),
            demo_city: "Rio de Janeiro".into(),
            city_lat: -22.9,
            city_lon: -43.1,
            llm_api_url: None,
            llm_api_key: None,
            llm_model: "test".into(),
            mfa_encryption_key: None,
            cookie_secure: false,
        };

        let result =
            translate_security_code(&client, &config, SecurityEventCode::PiiDetected).await;
        assert!(result.message.contains("informações pessoais"));
        assert_eq!(result.source, "mensagem local de segurança");

        let result_taint =
            translate_security_code(&client, &config, SecurityEventCode::TaintSinkBlocked).await;
        assert!(result_taint.message.contains("política de proteção"));
    }

    #[test]
    fn event_codes_have_standard_representations() {
        assert_eq!(SecurityEventCode::PiiDetected.as_str(), "PII_DETECTED");
        assert_eq!(
            SecurityEventCode::TaintSinkBlocked.as_str(),
            "TAINT_SINK_BLOCKED"
        );
        assert_eq!(
            SecurityEventCode::RateLimitTriggered.as_str(),
            "RATE_LIMIT_TRIGGERED"
        );
    }
}
