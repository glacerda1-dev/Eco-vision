#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub demo_city: String,
    pub city_lat: f64,
    pub city_lon: f64,
    pub llm_api_url: Option<String>,
    pub llm_api_key: Option<String>,
    pub llm_model: String,
    pub mfa_encryption_key: Option<String>,
    pub cookie_secure: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &self.database_url)
            .field("demo_city", &self.demo_city)
            .field("city_lat", &self.city_lat)
            .field("city_lon", &self.city_lon)
            .field("llm_api_url", &self.llm_api_url)
            .field("llm_api_key", &self.llm_api_key.as_ref().map(|_| "***"))
            .field("llm_model", &self.llm_model)
            .field(
                "mfa_encryption_key",
                &self.mfa_encryption_key.as_ref().map(|_| "***"),
            )
            .field("cookie_secure", &self.cookie_secure)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://data/eco_vision.db".to_owned()),
            demo_city: std::env::var("DEMO_CITY")
                .unwrap_or_else(|_| "Rio de Janeiro/RJ".to_owned()),
            city_lat: env_f64("CITY_LAT", -22.9068),
            city_lon: env_f64("CITY_LON", -43.1729),
            llm_api_url: std::env::var("LLM_API_URL").ok().filter(|s| !s.is_empty()),
            llm_api_key: std::env::var("LLM_API_KEY").ok().filter(|s| !s.is_empty()),
            llm_model: std::env::var("LLM_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_owned()),
            mfa_encryption_key: std::env::var("ECO_VISION_MFA_ENCRYPTION_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            cookie_secure: std::env::var("ECO_VISION_COOKIE_SECURE")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(false),
        }
    }
}

fn env_f64(name: &str, fallback: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(fallback)
}
