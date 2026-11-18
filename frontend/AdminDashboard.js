const byId = (id) => document.getElementById(id);
let administrator = null;
let twoFactorEnabled = false;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function resetLoginChallenge() {
  const challenge = byId("two-factor-login-field");
  const code = byId("admin-two-factor-code");
  if (challenge) challenge.hidden = true;
  if (code) code.value = "";
  const button = byId("login-button");
  if (button) button.textContent = "Entrar no painel";
}

function showLogin(message = "A conta de administrador é configurada pela equipe no ambiente do servidor.") {
  administrator = null;
  resetLoginChallenge();
  byId("login-card").hidden = false;
  byId("forbidden-card").hidden = true;
  byId("security-panel").hidden = true;
  byId("login-feedback").textContent = message;
}

function showForbidden() {
  administrator = null;
  byId("login-card").hidden = true;
  byId("security-panel").hidden = true;
  byId("forbidden-card").hidden = false;
}

function renderSecurityDashboard(data) {
  byId("blocked-count").textContent = data.blocked_pii_submissions;
  byId("outbound-count").textContent = data.outbound_taint_blocks;
  byId("rate-limit-count").textContent = data.rate_limited_submissions;
  byId("rate-limit-policy").textContent = `${data.max_reports_per_window} envios / ${data.window_seconds}s por IP`;
}

async function loadSecurityDashboard() {
  if (!administrator) return;
  try {
    const response = await fetch("/api/v1/security/dashboard", { credentials: "same-origin" });
    if (response.status === 401) return showLogin("Sua sessão expirou. Entre novamente para acessar a área administrativa.");
    if (response.status === 403) return showForbidden();
    if (!response.ok) throw new Error("Falha ao carregar indicadores de segurança.");
    renderSecurityDashboard(await response.json());
  } catch (_) {
    byId("page-feedback").textContent = "Os indicadores estão temporariamente indisponíveis.";
  }
}

async function loadAudit() {
  if (!administrator) return;
  const list = byId("audit-list");
  try {
    const response = await fetch("/api/v1/security/audit", { credentials: "same-origin" });
    if (response.status === 401) return showLogin("Sua sessão expirou. Entre novamente para acessar a área administrativa.");
    if (response.status === 403) return showForbidden();
    if (!response.ok) throw new Error("Falha ao consultar auditoria.");
    const events = await response.json();
    if (!events.length) {
      list.innerHTML = "<li>Nenhum evento de segurança recente.</li>";
      return;
    }
    const labels = {
      pii_scan_blocked: "Amostra de teste com padrão pessoal detectado",
      report_blocked_pii: "Relato bloqueado por possível dado pessoal",
      report_rate_limited: "Solicitação bloqueada pelo limite de envios",
      report_accepted: "Relato aceito com destinos de dados controlados",
      pii_scan_clean: "Amostra de teste sem padrão pessoal detectado"
    };
    list.innerHTML = events.slice(0, 8).map((event) => {
      const categories = event.finding_kinds.length ? ` · Padrões: ${event.finding_kinds.join(", ")}` : "";
      const sinkInfo = event.sink ? ` · Destino: ${event.sink}` : "";
      const decisionBadge = event.decision === "blocked" ? " [BLOQUEADO]" : (event.decision === "allowed" ? " [PERMITIDO]" : "");
      const reasonInfo = event.reason ? ` · ${event.reason}` : "";
      return `<li><strong>${escapeHtml(labels[event.event_type] || event.event_type)}${escapeHtml(decisionBadge)}</strong>${escapeHtml(categories)}${escapeHtml(sinkInfo)}<br><small>${escapeHtml(event.created_at)}${escapeHtml(reasonInfo)}</small></li>`;
    }).join("");
  } catch (_) {
    list.innerHTML = "<li>Auditoria temporariamente indisponível.</li>";
  }
}

async function loadAdminData() {
  await Promise.all([loadSecurityDashboard(), loadAudit()]);
}

function showMfaView(view) {
  for (const id of ["mfa-disabled-state", "mfa-setup-state", "mfa-recovery-state", "mfa-enabled-state"]) {
    byId(id).hidden = id !== view;
  }
}

function updateChangePassword2faVisibility() {
  const container = byId("change-password-2fa-container");
  if (!container) return;
  const currentPassword = byId("current-password")?.value || "";
  const newPassword = byId("new-password")?.value || "";
  const codeInput = byId("change-password-code");

  const shouldShow = twoFactorEnabled && currentPassword.trim().length > 0 && newPassword.length >= 12;
  container.hidden = !shouldShow;
  if (!shouldShow && codeInput) {
    codeInput.value = "";
  }
}

async function loadTwoFactorStatus() {
  if (!administrator) return;
  const badge = byId("mfa-status-badge");
  try {
    const response = await fetch("/api/v1/auth/2fa/status", { credentials: "same-origin" });
    if (response.status === 401) return showLogin("Sua sessão expirou. Entre novamente para acessar a área administrativa.");
    if (response.status === 403) return showForbidden();
    if (!response.ok) throw new Error("Falha ao consultar autenticação em duas etapas.");
    const { enabled } = await response.json();
    twoFactorEnabled = Boolean(enabled);
    updateChangePassword2faVisibility();
    showMfaView(enabled ? "mfa-enabled-state" : "mfa-disabled-state");
    badge.textContent = enabled ? "Ativada" : "Não ativada";
    badge.classList.toggle("is-enabled", enabled);
    byId("mfa-description").textContent = enabled
      ? "A autenticação em duas etapas protege o acesso administrativo."
      : "Ative um aplicativo autenticador para proteger o acesso administrativo.";
  } catch (_) {
    badge.textContent = "Indisponível";
    byId("mfa-feedback").textContent = "Não foi possível consultar a configuração de segurança.";
  }
}

async function checkCurrentSession() {
  try {
    const response = await fetch("/api/v1/auth/me", { credentials: "same-origin" });
    if (!response.ok) return showLogin();
    const profile = await response.json();
    if (profile.role !== "administrator") return showForbidden();
    administrator = profile;
    byId("login-card").hidden = true;
    byId("forbidden-card").hidden = true;
    byId("security-panel").hidden = false;
    await Promise.all([loadAdminData(), loadTwoFactorStatus()]);
  } catch (_) {
    showLogin("Não foi possível verificar a sessão. Tente novamente.");
  }
}

async function login(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = new FormData(form);
  const feedback = byId("login-feedback");
  const button = byId("login-button");
  button.disabled = true;
  feedback.textContent = "Verificando credenciais…";
  try {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: values.get("email"),
        password: values.get("password"),
        two_factor_code: values.get("two_factor_code")?.trim() || null
      })
    });
    const result = await response.json();
    if (!response.ok) {
      if (result.code === "TWO_FACTOR_REQUIRED") {
        byId("two-factor-login-field").hidden = false;
        byId("login-button").textContent = "Verificar código e entrar";
        feedback.textContent = result.message;
        byId("admin-two-factor-code").focus();
        return;
      }
      if (result.code === "INVALID_TWO_FACTOR_CODE") {
        byId("two-factor-login-field").hidden = false;
        byId("login-button").textContent = "Verificar código e entrar";
        feedback.textContent = result.message || "Código inválido. Tente novamente.";
        byId("admin-two-factor-code").focus();
        return;
      }
      resetLoginChallenge();
      feedback.textContent = result.message || "Credenciais inválidas.";
      return;
    }
    if (result.role !== "administrator") {
      showForbidden();
      return;
    }
    administrator = result;
    form.reset();
    byId("login-card").hidden = true;
    byId("security-panel").hidden = false;
    byId("page-feedback").textContent = "";
    await Promise.all([loadAdminData(), loadTwoFactorStatus()]);
  } catch (_) {
    feedback.textContent = "Não foi possível conectar ao serviço. Tente novamente.";
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  await fetch("/api/v1/auth/logout", { method: "POST", credentials: "same-origin" });
  showLogin("Sessão encerrada.");
}

async function startTwoFactorSetup(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const feedback = byId("mfa-feedback");
  feedback.textContent = "Preparando a configuração…";
  try {
    const response = await fetch("/api/v1/auth/2fa/setup", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: new FormData(form).get("password") })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Não foi possível iniciar a configuração.");
    byId("mfa-secret").textContent = result.secret;
    showMfaView("mfa-setup-state");
    byId("mfa-status-badge").textContent = "Configuração pendente";
    feedback.textContent = "Adicione a chave ao autenticador e confirme com o código atual.";
  } catch (error) {
    feedback.textContent = error.message || "Falha ao iniciar configuração.";
  }
}

async function confirmTwoFactorSetup(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const feedback = byId("mfa-feedback");
  feedback.textContent = "Validando código…";
  try {
    const response = await fetch("/api/v1/auth/2fa/confirm", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: new FormData(form).get("code") })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Código inválido. Confira o relógio do autenticador e tente novamente.");
    const list = byId("mfa-recovery-list");
    list.replaceChildren(...result.codes.map((code) => {
      const item = document.createElement("li");
      item.textContent = code;
      return item;
    }));
    byId("mfa-recovery-state").hidden = false;
    byId("mfa-setup-state").hidden = true;
    byId("mfa-disabled-state").hidden = true;
    byId("mfa-enabled-state").hidden = true;
    byId("mfa-status-badge").textContent = "Ativada";
    byId("mfa-status-badge").classList.add("is-enabled");
    feedback.textContent = "Salve os códigos de recuperação antes de fechar esta etapa.";
    form.reset();
  } catch (error) {
    feedback.textContent = error.message || "Não foi possível confirmar a configuração.";
  }
}

function dismissRecoveryCodes() {
  byId("mfa-recovery-list").replaceChildren();
  byId("mfa-secret").textContent = "";
  showLogin("Autenticação em duas etapas ativada. Entre novamente usando sua senha e o código do aplicativo.");
}

async function disableTwoFactor(event) {
  event.preventDefault();
  const values = new FormData(event.currentTarget);
  const feedback = byId("mfa-feedback");
  feedback.textContent = "Verificando credenciais…";
  try {
    const response = await fetch("/api/v1/auth/2fa/disable", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: values.get("password"), code: values.get("code") })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Não foi possível desativar a autenticação em duas etapas.");
    showLogin(result.message || "Segundo fator desativado. Entre novamente.");
  } catch (error) {
    feedback.textContent = error.message || "Falha ao desativar.";
  }
}

async function changePassword(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = new FormData(form);
  const feedback = byId("password-feedback");
  feedback.textContent = "Atualizando senha…";
  try {
    const response = await fetch("/api/v1/auth/password", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        current_password: values.get("current_password"),
        new_password: values.get("new_password"),
        two_factor_code: values.get("two_factor_code")?.trim() || null
      })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.message || "Não foi possível alterar a senha.");
    form.reset();
    updateChangePassword2faVisibility();
    showLogin(result.message || "Senha alterada. Entre novamente.");
  } catch (error) {
    feedback.textContent = error.message || "Falha ao atualizar senha.";
  }
}

async function runScanner() {
  const result = byId("scan-result");
  result.hidden = false;
  result.textContent = "Verificando uma amostra fictícia…";
  try {
    const response = await fetch("/api/v1/security/scan", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sample: "Amostra fictícia: demo@example.com" })
    });
    if (response.status === 401) return showLogin("Sua sessão expirou. Entre novamente.");
    if (response.status === 403) return showForbidden();
    if (!response.ok) throw new Error("Falha na verificação.");
    const data = await response.json();
    const decisions = data.taint_decisions.map((decision) => {
      const names = { private_database: "Banco privado", public_dashboard: "Painel público", external_weather_api: "API de clima", llm_provider: "Provedor de IA" };
      return `<li>${escapeHtml(names[decision.sink] || decision.sink)}: ${decision.allowed ? "permitido" : "bloqueado"}</li>`;
    }).join("");
    result.innerHTML = `<strong>${data.accepted ? "Nenhum padrão pessoal detectado" : "Padrão pessoal detectado e bloqueado"}</strong><br>${escapeHtml(data.citizen_message)}<ul>${decisions}</ul><small>Origem da mensagem: ${escapeHtml(data.translation_source)}. Amostra fictícia descartada.</small>`;
    await loadAdminData();
  } catch (_) {
    result.textContent = "Não foi possível executar a verificação agora.";
  }
}

byId("admin-login-form").addEventListener("submit", login);
for (const id of ["admin-email", "admin-password"]) {
  byId(id).addEventListener("input", () => {
    if (!byId("two-factor-login-field").hidden) {
      resetLoginChallenge();
      byId("login-feedback").textContent = "Credenciais alteradas. Entre para verificar se o segundo fator é necessário.";
    }
  });
}
byId("current-password")?.addEventListener("input", updateChangePassword2faVisibility);
byId("new-password")?.addEventListener("input", updateChangePassword2faVisibility);
byId("admin-logout").addEventListener("click", logout);
byId("forbidden-logout").addEventListener("click", logout);
byId("refresh-security").addEventListener("click", loadAdminData);
byId("run-scan").addEventListener("click", runScanner);
byId("mfa-setup-form").addEventListener("submit", startTwoFactorSetup);
byId("mfa-confirm-form").addEventListener("submit", confirmTwoFactorSetup);
byId("dismiss-recovery").addEventListener("click", dismissRecoveryCodes);
byId("mfa-disable-form").addEventListener("submit", disableTwoFactor);
byId("change-password-form").addEventListener("submit", changePassword);
checkCurrentSession();
