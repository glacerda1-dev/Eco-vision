-- 0004_structured_security_audit.sql
-- Auditoria de segurança estruturada com identificação de sink, decisão e motivo
ALTER TABLE security_audit ADD COLUMN sink TEXT NOT NULL DEFAULT 'private_database';
ALTER TABLE security_audit ADD COLUMN decision TEXT NOT NULL DEFAULT 'blocked';
ALTER TABLE security_audit ADD COLUMN reason TEXT NOT NULL DEFAULT '';

UPDATE security_audit SET decision = 'allowed', sink = 'private_database', reason = 'Persistência privada autorizada após validação PII' WHERE event_type = 'report_accepted';
UPDATE security_audit SET decision = 'blocked', sink = 'private_database', reason = 'Entrada bloqueada preventivamente por conter PII' WHERE event_type = 'report_blocked_pii';
UPDATE security_audit SET decision = 'blocked', sink = 'http_response', reason = 'Bloqueio por excesso de requisições por IP' WHERE event_type = 'report_rate_limited';
UPDATE security_audit SET decision = 'allowed', sink = 'system_log', reason = 'Verificação de amostra limpa' WHERE event_type = 'pii_scan_clean';
UPDATE security_audit SET decision = 'blocked', sink = 'system_log', reason = 'Amostra de teste continha PII' WHERE event_type = 'pii_scan_blocked';

CREATE INDEX IF NOT EXISTS idx_security_audit_decision ON security_audit(decision);
CREATE INDEX IF NOT EXISTS idx_security_audit_event_type ON security_audit(event_type);
