use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::{contracts::api_contracts::WeatherSummary, infrastructure::app_configuration::Config};

#[derive(Deserialize)]
struct ForecastResponse {
    current: Option<Current>,
    daily: Option<Daily>,
}
#[derive(Deserialize)]
struct Current {
    time: String,
    precipitation: Option<f64>,
    rain: Option<f64>,
    showers: Option<f64>,
}
#[derive(Deserialize)]
struct Daily {
    precipitation_probability_max: Option<Vec<u8>>,
}

pub async fn fetch_city_weather(
    client: &reqwest::Client,
    config: &Config,
) -> Result<WeatherSummary, reqwest::Error> {
    let response: ForecastResponse = client
        .get("https://api.open-meteo.com/v1/forecast")
        .query(&[
            ("latitude", config.city_lat.to_string()),
            ("longitude", config.city_lon.to_string()),
            ("current", "precipitation,rain,showers".to_owned()),
            ("daily", "precipitation_probability_max".to_owned()),
            ("timezone", "auto".to_owned()),
            ("forecast_days", "1".to_owned()),
        ])
        .timeout(std::time::Duration::from_secs(7))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let current = response.current;
    let amount = current
        .as_ref()
        .and_then(|c| c.precipitation)
        .or_else(|| current.as_ref().and_then(|c| c.rain))
        .or_else(|| current.as_ref().and_then(|c| c.showers))
        .unwrap_or(0.0);
    let probability = response
        .daily
        .and_then(|d| d.precipitation_probability_max)
        .and_then(|values| values.first().copied());
    let score = u16::from(probability.unwrap_or(0)) + (amount * 10.0).round() as u16;
    let risk_level = match score {
        0..=24 => "baixo",
        25..=59 => "atenção",
        _ => "alto",
    };
    let observed_at = current.and_then(|c| {
        DateTime::parse_from_rfc3339(&format!("{}:00Z", c.time))
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    });
    Ok(WeatherSummary {
        city: config.demo_city.clone(),
        precipitation_mm: amount,
        forecast_probability_percent: probability,
        risk_level: risk_level.to_owned(),
        source: "Open-Meteo (previsão pública; não é alerta oficial)".into(),
        observed_at,
    })
}
