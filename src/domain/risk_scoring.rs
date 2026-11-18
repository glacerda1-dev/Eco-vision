/// Índice explicável para protótipo: ocorrências abertas e graves elevam o valor.
pub fn citizen_risk_score(open_reports: i64, high_severity_reports: i64) -> u8 {
    let score = (open_reports.max(0) * 8 + high_severity_reports.max(0) * 12).clamp(0, 100);
    score as u8
}

pub fn risk_level(score: u8) -> &'static str {
    match score {
        0..=29 => "baixo",
        30..=59 => "atenção",
        _ => "alto",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_bounded_and_explainable() {
        assert_eq!(citizen_risk_score(0, 0), 0);
        assert_eq!(citizen_risk_score(3, 2), 48);
        assert_eq!(citizen_risk_score(100, 100), 100);
        assert_eq!(risk_level(48), "atenção");
    }
}
