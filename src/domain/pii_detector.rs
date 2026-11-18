use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PiiKind {
    Cpf,
    Rg,
    Email,
    Phone,
    PostalAddress,
    Cep,
    Credential,
    ApiKeyToken,
    HealthData,
}

impl PiiKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpf => "cpf",
            Self::Rg => "rg",
            Self::Email => "email",
            Self::Phone => "telefone",
            Self::PostalAddress => "endereço",
            Self::Cep => "cep",
            Self::Credential => "credencial",
            Self::ApiKeyToken => "token_api_key",
            Self::HealthData => "dado_de_saude",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct PiiFinding {
    pub kind: PiiKind,
}

// CPF sintático: formato tradicional 000.000.000-00 ou 11 dígitos com pontuação
static CPF_FORMAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\D)((?:\d{3}\.){2}\d{3}-\d{2})(?:$|\D)").unwrap());

// RG brasileiro: variações comuns (ex.: 12.345.678-9, 12.345.678-X, 1.234.567-8, ou precedido de RG/identidade)
static RG_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:rg|identidade|registro\s+geral|doc(?:umento)?)\s*[:=.]?\s*(\d{1,2}\.?\d{3}\.?\d{3}-?[0-9xX]|\d{7,9})\b|\b(\d{1,2}\.\d{3}\.\d{3}-[0-9xX])\b").unwrap()
});

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").unwrap());

static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\D)((?:\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}[-\s]?\d{4})(?:$|\D)").unwrap()
});

static CREDENTIAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(senha|password|passwd|secret|pwd)\s*[:=]\s*\S+").unwrap());

static API_KEY_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(bearer\s+[A-Za-z0-9\-._~+/]+=*|api[_\-\s]?key\s*[:=]\s*[A-Za-z0-9_\-]{8,}|token\s*[:=]\s*[A-Za-z0-9_\-\.]{12,}|ghp_[A-Za-z0-9]{36}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b").unwrap()
});

static POSTAL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:rua|avenida|av\.?|travessa|alameda|rodovia|estrada|praça)\s+[^,\n]{2,70},?\s*(?:n[º°.]?\s*)?\d{1,5}\b").unwrap()
});

static CEP_FORMAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:cep\s*[:=]?\s*)?(\d{5}-\d{3})\b|\bcep\s*[:=]?\s*(\d{8})\b").unwrap()
});

static HEALTH_DATA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:diagn[oó]stico|laudo|medica[cç][aã]o|medicamento|condi[cç][aã]o de sa[uú]de|prontu[aá]rio|paciente|hospitaliza[cç][aã]o)\s*[:=]\s*\S+|\bCID[-\s]?[A-Z0-9]{2,}\b").unwrap()
});

/// Identifica categorias sem devolver o trecho encontrado, evitando repetir PII na resposta ou logs.
pub fn scan_pii(text: &str) -> Vec<PiiFinding> {
    let mut findings = Vec::new();

    // 1. CPF: reconhece tanto formato sintático (ex: "123.456.789-00") quanto verificado
    if CPF_FORMAT.is_match(text) {
        findings.push(PiiFinding { kind: PiiKind::Cpf });
    } else {
        // Fallback: se houver 11 dígitos que validam pelo algoritmo de CPF
        let digits_only: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits_only.len() == 11 && is_valid_cpf(&digits_only) {
            findings.push(PiiFinding { kind: PiiKind::Cpf });
        }
    }

    // 2. RG
    if RG_FORMAT.is_match(text) {
        findings.push(PiiFinding { kind: PiiKind::Rg });
    }

    // 3. E-mail
    if EMAIL.is_match(text) {
        findings.push(PiiFinding {
            kind: PiiKind::Email,
        });
    }

    // 4. Telefone
    if PHONE.is_match(text) {
        findings.push(PiiFinding {
            kind: PiiKind::Phone,
        });
    }

    // 5. Credenciais
    if CREDENTIAL.is_match(text) {
        findings.push(PiiFinding {
            kind: PiiKind::Credential,
        });
    }

    // 6. Tokens e API Keys
    if API_KEY_TOKEN.is_match(text) {
        findings.push(PiiFinding {
            kind: PiiKind::ApiKeyToken,
        });
    }

    // 7. Endereço
    if POSTAL_ADDRESS.is_match(text) {
        findings.push(PiiFinding {
            kind: PiiKind::PostalAddress,
        });
    }

    // 8. CEP
    if CEP_FORMAT.is_match(text) {
        findings.push(PiiFinding { kind: PiiKind::Cep });
    }

    // 9. Informações de saúde / CID
    if HEALTH_DATA.is_match(text) {
        findings.push(PiiFinding {
            kind: PiiKind::HealthData,
        });
    }

    findings
}

/// Percorre recursivamente estruturas JSON (objetos, arrays e valores escalares),
/// avaliando PII tanto pelo conteúdo dos valores quanto pelo nome das chaves.
pub fn scan_json_pii(value: &serde_json::Value) -> Vec<PiiFinding> {
    let mut findings = Vec::new();
    collect_json_pii(value, &mut findings);
    findings.sort_by_key(|f| f.kind.as_str());
    findings.dedup();
    findings
}

fn collect_json_pii(value: &serde_json::Value, findings: &mut Vec<PiiFinding>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let normalized_key = key.trim().to_lowercase();
                // Verificação pelo nome do campo/chave sensível
                if !val.is_null() && !val_is_empty_str(val) {
                    let maybe_pii = match normalized_key.as_str() {
                        "cpf" | "documento" => Some(PiiKind::Cpf),
                        "rg" | "registro_geral" | "identidade" => Some(PiiKind::Rg),
                        "email" | "e-mail" | "correio_eletronico" => Some(PiiKind::Email),
                        "telefone" | "celular" | "fone" | "phone" | "tel" => Some(PiiKind::Phone),
                        "senha" | "password" | "passwd" | "secret" | "pwd" => {
                            Some(PiiKind::Credential)
                        }
                        "token" | "api_key" | "apikey" | "auth_token" | "access_token" => {
                            Some(PiiKind::ApiKeyToken)
                        }
                        "endereco" | "endereço" | "logradouro" | "rua" => {
                            Some(PiiKind::PostalAddress)
                        }
                        "cep" => Some(PiiKind::Cep),
                        "diagnostico" | "diagnóstico" | "laudo" | "cid" | "medicamento"
                        | "saude" | "saúde" => Some(PiiKind::HealthData),
                        _ => None,
                    };
                    if let Some(kind) = maybe_pii {
                        findings.push(PiiFinding { kind });
                    }
                }
                // Analisa o valor associado à chave recursivamente
                collect_json_pii(val, findings);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_json_pii(item, findings);
            }
        }
        serde_json::Value::String(s) => {
            findings.extend(scan_pii(s));
        }
        _ => {}
    }
}

fn val_is_empty_str(val: &serde_json::Value) -> bool {
    if let serde_json::Value::String(s) = val {
        s.trim().is_empty()
    } else {
        false
    }
}

/// Mascara um identificador de forma segura quando a exibição parcial for necessária.
pub fn mask_identifier(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 4 {
        return "*".repeat(chars.len());
    }
    let visible_prefix = &chars[..1];
    let visible_suffix = &chars[chars.len().saturating_sub(2)..];
    let masked_len = chars.len().saturating_sub(3);
    format!(
        "{}{}{}",
        visible_prefix.iter().collect::<String>(),
        "*".repeat(masked_len),
        visible_suffix.iter().collect::<String>()
    )
}

/// Valida se os dígitos verificadores do CPF são matematicamente corretos.
pub fn is_valid_cpf(value: &str) -> bool {
    let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 11 || digits.iter().all(|digit| *digit == digits[0]) {
        return false;
    }
    let check = |slice: &[u32], weights: &[u32]| -> u32 {
        let sum: u32 = slice
            .iter()
            .zip(weights)
            .map(|(digit, weight)| digit * weight)
            .sum();
        let remainder = (sum * 10) % 11;
        if remainder == 10 { 0 } else { remainder }
    };
    check(&digits[..9], &[10, 9, 8, 7, 6, 5, 4, 3, 2]) == digits[9]
        && check(&digits[..10], &[11, 10, 9, 8, 7, 6, 5, 4, 3, 2]) == digits[10]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_multiple_sensitive_categories_without_returning_values() {
        let findings = scan_pii("Meu email é pessoa@example.com e CPF 529.982.247-25");
        assert!(findings.iter().any(|f| f.kind == PiiKind::Email));
        assert!(findings.iter().any(|f| f.kind == PiiKind::Cpf));
        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(!serialized.contains("529"));
        assert!(!serialized.contains("pessoa@example.com"));
    }

    #[test]
    fn catches_phone_and_credentials() {
        let findings = scan_pii("Contato (11) 98765-4321; senha=supersecreta");
        assert!(findings.iter().any(|f| f.kind == PiiKind::Phone));
        assert!(findings.iter().any(|f| f.kind == PiiKind::Credential));
    }

    #[test]
    fn detects_syntactic_cpf_even_with_invalid_checksum() {
        // Exemplo direto solicitado na Global Solutions: "123.456.789-00"
        let findings = scan_pii("O documento do morador é 123.456.789-00");
        assert!(
            findings.iter().any(|f| f.kind == PiiKind::Cpf),
            "Padrão sintático de CPF deve ser detectado para proteção de dados mesmo se dígitos verificadores forem inválidos."
        );
    }

    #[test]
    fn detects_valid_cpf() {
        assert!(is_valid_cpf("529.982.247-25"));
        let findings = scan_pii("CPF 529.982.247-25");
        assert!(findings.iter().any(|f| f.kind == PiiKind::Cpf));
    }

    #[test]
    fn detects_rg_brazilian_formats() {
        let f1 = scan_pii("Identidade: RG 12.345.678-9 SSP/SP");
        assert!(f1.iter().any(|f| f.kind == PiiKind::Rg));

        let f2 = scan_pii("Apresentou o doc 12.345.678-X");
        assert!(f2.iter().any(|f| f.kind == PiiKind::Rg));
    }

    #[test]
    fn detects_cep_and_postal_address() {
        let f1 = scan_pii("Morador reside no CEP 01310-100 na Avenida Paulista, 1000");
        assert!(f1.iter().any(|f| f.kind == PiiKind::Cep));
        assert!(f1.iter().any(|f| f.kind == PiiKind::PostalAddress));
    }

    #[test]
    fn detects_api_key_and_tokens() {
        let findings = scan_pii(
            "Minha chave é api_key = sk_live_1234567890abcdef e token = ghp_123456789012345678901234567890123456",
        );
        assert!(findings.iter().any(|f| f.kind == PiiKind::ApiKeyToken));
    }

    #[test]
    fn detects_explicit_health_details_and_street_addresses() {
        let findings = scan_pii("Moro na Rua das Flores, 123; diagnóstico: asma e CID-J45");
        assert!(findings.iter().any(|f| f.kind == PiiKind::PostalAddress));
        assert!(findings.iter().any(|f| f.kind == PiiKind::HealthData));
    }

    #[test]
    fn scans_nested_json_objects_and_arrays() {
        let sample = serde_json::json!({
            "relato": "Alagamento na esquina",
            "documento": "123.456.789-00",
            "email": "pessoa@email.com",
            "usuario": {
                "telefone": "(11) 98765-4321",
                "detalhes": [
                    { "cep": "01310-100" },
                    { "medicamento": "insulina" }
                ]
            }
        });
        let findings = scan_json_pii(&sample);
        assert!(findings.iter().any(|f| f.kind == PiiKind::Cpf));
        assert!(findings.iter().any(|f| f.kind == PiiKind::Email));
        assert!(findings.iter().any(|f| f.kind == PiiKind::Phone));
        assert!(findings.iter().any(|f| f.kind == PiiKind::Cep));
        assert!(findings.iter().any(|f| f.kind == PiiKind::HealthData));
    }

    #[test]
    fn json_without_pii_returns_clean() {
        let sample = serde_json::json!({
            "categoria": "Alagamento em via",
            "bairro": "Centro",
            "detalhes": "Água subiu 30cm próximo à praça pública após a chuva",
            "gravidade": "high"
        });
        let findings = scan_json_pii(&sample);
        assert!(findings.is_empty());
    }

    #[test]
    fn mask_identifier_works_correctly() {
        let masked = mask_identifier("usuario@exemplo.com");
        assert!(masked.starts_with('u'));
        assert!(masked.ends_with("om"));
        assert!(masked.contains('*'));
    }
}
