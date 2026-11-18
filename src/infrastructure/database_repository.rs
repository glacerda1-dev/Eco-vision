use std::borrow::Cow;
use std::str::FromStr;

use sqlx::{
    FromRow, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::{
    contracts::api_contracts::{
        AuditSummary, CitizenPrivacyStatus, ReportSummary, Severity, UserProfile,
    },
    security::taint_policy::AccessRole,
};

#[derive(Clone)]
pub struct DatabaseRepository {
    pool: SqlitePool,
}

#[derive(Debug)]
pub struct DashboardCounts {
    pub open_reports: i64,
    pub high_severity_reports: i64,
    pub resolved_reports: i64,
}

#[derive(Debug)]
pub struct SecurityCounts {
    pub blocked_pii_submissions: i64,
    pub outbound_taint_blocks: i64,
}

#[derive(FromRow)]
struct ReportRow {
    id: String,
    category: String,
    neighborhood: String,
    severity: String,
    status: String,
    created_at: String,
    is_demo: i64,
}

#[derive(FromRow)]
struct AuditRow {
    event_type: String,
    finding_kinds: String,
    taint_decision: String,
    sink: String,
    decision: String,
    reason: String,
    created_at: String,
}

#[derive(FromRow)]
struct AccountRow {
    id: String,
    email: String,
    password_hash: String,
    role: String,
    two_factor_secret_encrypted: Option<String>,
    two_factor_enabled_at: Option<String>,
}

impl AccountRow {
    fn into_stored_account(self) -> Option<StoredAccount> {
        Some(StoredAccount {
            id: self.id,
            email: self.email,
            password_hash: self.password_hash,
            role: self.role.parse().ok()?,
            two_factor_secret_encrypted: self.two_factor_secret_encrypted,
            two_factor_enabled: self.two_factor_enabled_at.is_some(),
        })
    }
}

#[derive(FromRow)]
struct SessionAccountRow {
    id: String,
    email: String,
    role: String,
}

#[derive(Clone, Debug)]
pub struct StoredAccount {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub role: AccessRole,
    pub two_factor_secret_encrypted: Option<String>,
    pub two_factor_enabled: bool,
}

#[derive(Clone, Debug)]
pub struct SessionAccount {
    pub id: String,
    pub profile: UserProfile,
}

impl DatabaseRepository {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        if let Some(path) = database_url.strip_prefix("sqlite://")
            && path != ":memory:"
            && let Some(parent) = std::path::Path::new(path).parent()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| sqlx::Error::Io(std::io::Error::other(error)))?;
        }

        let max_connections = if database_url == "sqlite::memory:" {
            1
        } else {
            5
        };
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate_and_seed(&self) -> Result<(), sqlx::Error> {
        let definitions = [
            (
                1,
                "initial",
                include_str!("../../migrations/0001_initial.sql"),
            ),
            (
                2,
                "user_accounts_and_sessions",
                include_str!("../../migrations/0002_user_accounts_and_sessions.sql"),
            ),
            (
                3,
                "administrator_two_factor",
                include_str!("../../migrations/0003_administrator_two_factor.sql"),
            ),
            (
                4,
                "structured_security_audit",
                include_str!("../../migrations/0004_structured_security_audit.sql"),
            ),
        ];

        let migrations = definitions
            .into_iter()
            .map(|(version, name, sql)| {
                sqlx::migrate::Migration::new(
                    version,
                    Cow::Borrowed(name),
                    sqlx::migrate::MigrationType::Simple,
                    Cow::Borrowed(sql),
                    false,
                )
            })
            .collect();

        let migrator = sqlx::migrate::Migrator {
            migrations: Cow::Owned(migrations),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        migrator
            .run(&self.pool)
            .await
            .map_err(|error| sqlx::Error::Migrate(Box::new(error)))?;

        let demo_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE is_demo = 1")
            .fetch_one(&self.pool)
            .await?;
        if demo_count == 0 {
            let examples = [
                (
                    "Alagamento em via",
                    "Água acumulada após chuva forte; exemplo demonstrativo.",
                    "Centro",
                    Severity::High,
                ),
                (
                    "Bueiro obstruído",
                    "Escoamento lento próximo a uma praça; exemplo demonstrativo.",
                    "Praça da Bandeira",
                    Severity::Medium,
                ),
                (
                    "Ponto de alagamento",
                    "Trecho baixo com passagem difícil para pedestres; exemplo demonstrativo.",
                    "Jardim Botânico",
                    Severity::High,
                ),
                (
                    "Risco de enxurrada",
                    "Relato comunitário simulado para apresentação; exemplo demonstrativo.",
                    "Tijuca",
                    Severity::Low,
                ),
            ];
            for (category, details, neighborhood, severity) in examples {
                sqlx::query(
                    "INSERT INTO reports (id, category, details, neighborhood, severity, is_demo) VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, 1)",
                )
                .bind(category)
                .bind(details)
                .bind(neighborhood)
                .bind(severity.as_str())
                .execute(&self.pool)
                .await?;
            }
        } else {
            let updates = [
                ("Praça da Bandeira", "Vila Nova"),
                ("Jardim Botânico", "Jardim Aurora"),
                ("Tijuca", "Parque Sul"),
            ];
            for (new_bairro, old_bairro) in updates {
                sqlx::query(
                    "UPDATE reports SET neighborhood = ? WHERE is_demo = 1 AND neighborhood = ?",
                )
                .bind(new_bairro)
                .bind(old_bairro)
                .execute(&self.pool)
                .await?;
            }
        }
        Ok(())
    }

    pub async fn find_account_by_email(
        &self,
        email: &str,
    ) -> Result<Option<StoredAccount>, sqlx::Error> {
        let row = sqlx::query_as::<_, AccountRow>(
            "SELECT id, email, password_hash, role, two_factor_secret_encrypted, two_factor_enabled_at FROM users WHERE email = ? COLLATE NOCASE",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(AccountRow::into_stored_account))
    }

    pub async fn find_account_by_id(&self, id: &str) -> Result<Option<StoredAccount>, sqlx::Error> {
        let row = sqlx::query_as::<_, AccountRow>(
            "SELECT id, email, password_hash, role, two_factor_secret_encrypted, two_factor_enabled_at FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(AccountRow::into_stored_account))
    }

    pub async fn create_citizen_account(
        &self,
        id: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, 'user') ON CONFLICT(email) DO NOTHING",
        )
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn bootstrap_administrator(
        &self,
        id: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let previous_role: Option<String> =
            sqlx::query_scalar("SELECT role FROM users WHERE email = ? COLLATE NOCASE")
                .bind(email)
                .fetch_optional(&mut *transaction)
                .await?;
        sqlx::query(
            "DELETE FROM user_sessions WHERE user_id IN (SELECT id FROM users WHERE role = 'administrator' AND email <> ? COLLATE NOCASE)",
        )
            .bind(email)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE users SET role = 'user', two_factor_secret_encrypted = NULL, two_factor_pending_secret_encrypted = NULL, two_factor_enabled_at = NULL WHERE role = 'administrator' AND email <> ? COLLATE NOCASE",
        )
        .bind(email)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM admin_recovery_codes WHERE user_id IN (SELECT id FROM users WHERE role = 'user')",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, 'administrator') ON CONFLICT(email) DO UPDATE SET password_hash = excluded.password_hash, role = 'administrator', two_factor_secret_encrypted = NULL, two_factor_pending_secret_encrypted = NULL, two_factor_enabled_at = NULL",
        )
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM admin_recovery_codes WHERE user_id = (SELECT id FROM users WHERE email = ? COLLATE NOCASE)",
        )
        .bind(email)
        .execute(&mut *transaction)
        .await?;
        if previous_role.as_deref() != Some("administrator") {
            sqlx::query(
                "DELETE FROM user_sessions WHERE user_id = (SELECT id FROM users WHERE email = ? COLLATE NOCASE)",
            )
            .bind(email)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn save_pending_two_factor_secret(
        &self,
        user_id: &str,
        encrypted_secret: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE users SET two_factor_pending_secret_encrypted = ? WHERE id = ? AND role = 'administrator' AND two_factor_enabled_at IS NULL",
        )
        .bind(encrypted_secret)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn pending_two_factor_secret(
        &self,
        user_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT two_factor_pending_secret_encrypted FROM users WHERE id = ? AND role = 'administrator'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map(Option::flatten)
    }

    pub async fn enable_two_factor(
        &self,
        user_id: &str,
        recovery_hashes: &[String],
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE users SET two_factor_secret_encrypted = two_factor_pending_secret_encrypted, two_factor_pending_secret_encrypted = NULL, two_factor_enabled_at = CURRENT_TIMESTAMP WHERE id = ? AND role = 'administrator' AND two_factor_enabled_at IS NULL AND two_factor_pending_secret_encrypted IS NOT NULL",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM admin_recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        for hash in recovery_hashes {
            sqlx::query(
                "INSERT INTO admin_recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(hash)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn two_factor_enabled(&self, user_id: &str) -> Result<bool, sqlx::Error> {
        let enabled: Option<Option<String>> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT two_factor_enabled_at FROM users WHERE id = ? AND role = 'administrator'",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(enabled.flatten().is_some())
    }

    pub async fn consume_recovery_code(
        &self,
        user_id: &str,
        code_hash: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE admin_recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
        )
        .bind(user_id)
        .bind(code_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn disable_two_factor_and_revoke_sessions(
        &self,
        user_id: &str,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "UPDATE users SET two_factor_secret_encrypted = NULL, two_factor_pending_secret_encrypted = NULL, two_factor_enabled_at = NULL WHERE id = ? AND role = 'administrator'",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM admin_recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn update_password_and_revoke_sessions(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM user_sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM user_sessions WHERE expires_at <= unixepoch()")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn create_session(
        &self,
        token_hash: &str,
        user_id: &str,
        expires_at: i64,
    ) -> Result<(), sqlx::Error> {
        self.cleanup_expired_sessions().await?;
        sqlx::query("INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
            .bind(token_hash)
            .bind(user_id)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn session_account(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<SessionAccount>, sqlx::Error> {
        let row = sqlx::query_as::<_, SessionAccountRow>(
            "SELECT users.id, users.email, users.role FROM user_sessions JOIN users ON users.id = user_sessions.user_id WHERE user_sessions.token_hash = ? AND user_sessions.expires_at > ?",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|row| {
            Some(SessionAccount {
                id: row.id,
                profile: UserProfile {
                    email: row.email,
                    role: row.role.parse().ok()?,
                },
            })
        }))
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM user_sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_reports(&self) -> Result<Vec<ReportSummary>, sqlx::Error> {
        let rows = sqlx::query_as::<_, ReportRow>(
            "SELECT id, category, neighborhood, severity, status, created_at, is_demo FROM reports ORDER BY created_at DESC LIMIT 100",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| ReportSummary {
                id: row.id,
                category: row.category,
                neighborhood: row.neighborhood,
                severity: row.severity.parse().unwrap_or(Severity::Low),
                status: row.status,
                created_at: row.created_at,
                demonstrative: row.is_demo != 0,
            })
            .collect())
    }

    pub async fn dashboard_counts(&self) -> Result<DashboardCounts, sqlx::Error> {
        let open_reports = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE status = 'open'")
            .fetch_one(&self.pool)
            .await?;
        let high_severity_reports = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reports WHERE status = 'open' AND severity = 'high'",
        )
        .fetch_one(&self.pool)
        .await?;
        let resolved_reports =
            sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE status = 'resolved'")
                .fetch_one(&self.pool)
                .await?;
        Ok(DashboardCounts {
            open_reports,
            high_severity_reports,
            resolved_reports,
        })
    }

    pub async fn security_counts(&self) -> Result<SecurityCounts, sqlx::Error> {
        let blocked_pii_submissions = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_audit WHERE event_type = 'report_blocked_pii' AND decision = 'blocked'",
        )
        .fetch_one(&self.pool)
        .await?;
        let outbound_taint_blocks = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_audit WHERE decision = 'blocked' AND sink != 'private_database'",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(SecurityCounts {
            blocked_pii_submissions,
            outbound_taint_blocks,
        })
    }

    pub async fn citizen_privacy_status(&self) -> Result<CitizenPrivacyStatus, sqlx::Error> {
        let blocked_preventions_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_audit WHERE event_type = 'report_blocked_pii' AND decision = 'blocked'",
        )
        .fetch_one(&self.pool)
        .await?;

        let last_blocked: Option<String> = sqlx::query_scalar(
            "SELECT created_at FROM security_audit WHERE event_type = 'report_blocked_pii' ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        let recent_block_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM security_audit WHERE event_type = 'report_blocked_pii' AND datetime(created_at) >= datetime('now', '-24 hours')",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        let (status, status_label, message) = if recent_block_count > 0 {
            (
                "yellow".to_owned(),
                "Prevenção acionada recentemente".to_owned(),
                "Envios com dados pessoais foram prevenidos nas últimas 24h. O painel público e integrações externas permanecem intactos.".to_owned(),
            )
        } else {
            (
                "green".to_owned(),
                "Operação normal / Proteções ativas".to_owned(),
                "Todas as camadas de proteção de dados e privacidade estão ativas e nenhum dado sensível foi exposto.".to_owned(),
            )
        };

        Ok(CitizenPrivacyStatus {
            status,
            status_label,
            message,
            blocked_preventions_count,
            last_event_at: last_blocked,
        })
    }

    pub async fn insert_report(
        &self,
        id: &str,
        user_id: &str,
        category: &str,
        details: &str,
        neighborhood: &str,
        severity: Severity,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO reports (id, category, details, neighborhood, severity, status, is_demo, user_id) VALUES (?, ?, ?, ?, ?, 'open', 0, ?)",
        )
        .bind(id)
        .bind(category)
        .bind(details)
        .bind(neighborhood)
        .bind(severity.as_str())
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_security_event(
        &self,
        event_type: &str,
        finding_kinds: &[String],
        taint_decision: &str,
        sink: &str,
        decision: &str,
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        let serialized_findings =
            serde_json::to_string(finding_kinds).unwrap_or_else(|_| "[]".to_owned());
        sqlx::query(
            "INSERT INTO security_audit (event_type, finding_kinds, taint_decision, sink, decision, reason) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(event_type)
        .bind(serialized_findings)
        .bind(taint_decision)
        .bind(sink)
        .bind(decision)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_security_events(&self) -> Result<Vec<AuditSummary>, sqlx::Error> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT event_type, finding_kinds, taint_decision, sink, decision, reason, created_at FROM security_audit ORDER BY id DESC LIMIT 30",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| AuditSummary {
                event_type: row.event_type,
                finding_kinds: serde_json::from_str(&row.finding_kinds).unwrap_or_default(),
                taint_decision: row.taint_decision,
                sink: row.sink,
                decision: row.decision,
                reason: row.reason,
                created_at: row.created_at,
            })
            .collect())
    }

    pub async fn report_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(*) FROM reports")
            .fetch_one(&self.pool)
            .await
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}
