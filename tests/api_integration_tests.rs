use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use eco_vision::{
    application::eco_vision_service::EcoVisionService,
    infrastructure::{app_configuration::Config, database_repository::DatabaseRepository},
    presentation::http_api::{self, AppState},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "administrator@example.test";
const ADMIN_PASSWORD: &str = "TestAdministrator!234";
const USER_EMAIL: &str = "citizen@example.test";
const USER_PASSWORD: &str = "TestCitizenPassword!234";

async fn test_app() -> (axum::Router, String, String) {
    let repository = DatabaseRepository::connect("sqlite::memory:")
        .await
        .unwrap();
    repository.migrate_and_seed().await.unwrap();
    let config = Config {
        database_url: "sqlite::memory:".into(),
        demo_city: "Cidade de teste".into(),
        city_lat: -23.55,
        city_lon: -46.63,
        llm_api_url: None,
        llm_api_key: None,
        llm_model: "local-test".into(),
        mfa_encryption_key: None,
        cookie_secure: false,
    };
    let service = EcoVisionService::new(repository, config).unwrap();
    service
        .bootstrap_administrator(Some(ADMIN_EMAIL), Some(ADMIN_PASSWORD))
        .await
        .unwrap();
    let admin = service
        .login_user(ADMIN_EMAIL, ADMIN_PASSWORD)
        .await
        .unwrap();
    let user = service
        .register_user(USER_EMAIL, USER_PASSWORD)
        .await
        .unwrap();
    let app = http_api::router().with_state(AppState::new(service));
    (
        app,
        format!("eco_vision_session={}", admin.token),
        format!("eco_vision_session={}", user.token),
    )
}

async fn response_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn create_report_request(cookie: Option<&str>, details: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/reports")
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder
        .body(Body::from(
            json!({
                "category":"Alagamento em via", "details":details,
                "neighborhood":"Centro", "severity":"medium"
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn report_with_pii_is_blocked_and_details_are_visible_only_to_admin() {
    let (app, admin_cookie, user_cookie) = test_app().await;
    let unauthenticated = app
        .clone()
        .oneshot(create_report_request(None, "Relato comum."))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(create_report_request(
            Some(&user_cookie),
            "Meu contato é pessoa@example.com",
        ))
        .await
        .unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "PII_DETECTED");
    let msg = body["message"].as_str().unwrap();
    assert!(
        msg.contains("dados pessoais") || msg.contains("informações pessoais"),
        "Mensagem retornada: {msg}"
    );
    assert!(body.get("findings").is_none());
    assert!(!body.to_string().contains("pessoa@example.com"));

    let user_security = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/security/audit")
                .header("cookie", user_cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(user_security.status(), StatusCode::FORBIDDEN);

    let audit = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/security/audit")
                .header("cookie", admin_cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, audit_body) = response_json(audit).await;
    assert_eq!(status, StatusCode::OK);
    assert!(audit_body.to_string().contains("email"));
    assert!(!audit_body.to_string().contains("pessoa@example.com"));

    let public_dashboard = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (_, public_body) = response_json(public_dashboard).await;
    assert!(public_body.get("blocked_pii_submissions").is_none());

    let admin_dashboard = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security/dashboard")
                .header("cookie", admin_cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, admin_body) = response_json(admin_dashboard).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(admin_body["blocked_pii_submissions"], 1);
}

#[tokio::test]
async fn accepted_report_requires_a_session_and_public_list_omits_free_text() {
    let (app, _, user_cookie) = test_app().await;
    let create = app
        .clone()
        .oneshot(create_report_request(
            Some(&user_cookie),
            "Água cobre parte da calçada após chuva.",
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let list = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/reports")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(list).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.to_string().contains("Alagamento em via"));
    assert!(body.to_string().contains("Centro"));
    assert!(!body.to_string().contains("Água cobre parte da calçada"));
}

#[tokio::test]
async fn registration_cannot_choose_administrator_role() {
    let (app, _, _) = test_app().await;
    let response = app.oneshot(Request::builder().method("POST").uri("/api/v1/auth/register").header("content-type", "application/json").body(Body::from(json!({
        "email":"self-promote@example.test", "password":"ValidCitizenPassword!234", "role":"administrator"
    }).to_string())).unwrap()).await.unwrap();
    let cookie_was_set = response.headers().contains_key("set-cookie");
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["role"], "user");
    assert!(cookie_was_set);
}

#[tokio::test]
async fn security_scan_is_available_only_to_administrator() {
    let (app, admin_cookie, user_cookie) = test_app().await;
    let request = |cookie: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/security/scan")
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .body(Body::from(
                json!({"sample":"teste@example.com"}).to_string(),
            ))
            .unwrap()
    };
    let forbidden = app.clone().oneshot(request(&user_cookie)).await.unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let response = app.oneshot(request(&admin_cookie)).await.unwrap();
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.to_string().contains("email"));
    assert!(body.to_string().contains("external_weather_api"));
    assert!(!body.to_string().contains("teste@example.com"));
}

#[tokio::test]
async fn report_rate_limit_is_counted_in_administrator_dashboard() {
    let (app, admin_cookie, user_cookie) = test_app().await;
    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(create_report_request(
                Some(&user_cookie),
                "Água cobre parte da calçada.",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let limited = app
        .clone()
        .oneshot(create_report_request(Some(&user_cookie), "Outro relato."))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers().contains_key("retry-after"));

    let dashboard = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security/dashboard")
                .header("cookie", admin_cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body) = response_json(dashboard).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["rate_limited_submissions"], 1);
    assert_eq!(body["max_reports_per_window"], 5);
}

#[tokio::test]
async fn sqlite_file_and_parent_directory_are_created_automatically() {
    let relative_path = format!("data/test-{}.db", Uuid::new_v4());
    let url = format!("sqlite://{relative_path}");
    let repository = DatabaseRepository::connect(&url).await.unwrap();
    repository.migrate_and_seed().await.unwrap();
    let count = repository.report_count().await.unwrap();
    repository.close().await;
    assert_eq!(count, 4);
    assert!(std::path::Path::new(&relative_path).exists());
    std::fs::remove_file(&relative_path).unwrap();
}

#[tokio::test]
async fn responses_include_security_headers() {
    let (app, _, _) = test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get("referrer-policy")
            .and_then(|v| v.to_str().ok()),
        Some("strict-origin-when-cross-origin")
    );
    assert!(
        response.headers().get("content-security-policy").is_some(),
        "content-security-policy header should be present"
    );
}

#[tokio::test]
async fn privacy_status_endpoint_returns_valid_privacy_model() {
    let (app, _, _) = test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/privacy/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "green");
    assert!(
        body["status_label"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("normal")
    );
    assert!(body["message"].as_str().is_some());
    assert_eq!(body["blocked_preventions_count"], 0);
}

#[tokio::test]
async fn syntactic_cpf_is_blocked_even_with_invalid_checksum() {
    let (app, _, user_cookie) = test_app().await;
    let response = app
        .oneshot(create_report_request(
            Some(&user_cookie),
            "Documento do morador: 123.456.789-00",
        ))
        .await
        .unwrap();

    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "PII_DETECTED");
}

#[tokio::test]
async fn structured_audit_contains_sink_and_decision() {
    let (app, admin_cookie, user_cookie) = test_app().await;
    // Trigger PII block
    let _ = app
        .clone()
        .oneshot(create_report_request(
            Some(&user_cookie),
            "Meu RG é 12.345.678-9",
        ))
        .await
        .unwrap();

    // Query audit as admin
    let audit = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/security/audit")
                .header("cookie", admin_cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let (status, body) = response_json(audit).await;
    assert_eq!(status, StatusCode::OK);
    let events = body.as_array().expect("audit array");
    let pii_event = events
        .iter()
        .find(|e| e["event_type"] == "report_blocked_pii")
        .expect("report_blocked_pii event");

    assert_eq!(pii_event["sink"], "private_database");
    assert_eq!(pii_event["decision"], "blocked");
    assert!(pii_event["finding_kinds"].to_string().contains("rg"));
}
