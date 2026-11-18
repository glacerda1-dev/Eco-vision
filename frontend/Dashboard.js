const byId = (id) => document.getElementById(id);
let currentUser = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

async function getJson(path) {
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) throw new Error("Não foi possível carregar os dados.");
  return response.json();
}

function showToast(message) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 2800);
}

function renderAccount() {
  const signedIn = Boolean(currentUser);
  byId("account-button").hidden = signedIn;
  byId("account-label").hidden = !signedIn;
  byId("logout-button").hidden = !signedIn;
  byId("account-label").textContent = signedIn ? currentUser.email : "";
  byId("admin-link").hidden = !signedIn || currentUser.role !== "administrator";
  byId("auth-prompt").hidden = signedIn;
  byId("report-form").hidden = !signedIn;
  if (!signedIn) byId("form-feedback").className = "feedback";
}

async function loadCurrentUser() {
  try {
    const response = await fetch("/api/v1/auth/me", { credentials: "same-origin" });
    currentUser = response.ok ? await response.json() : null;
  } catch (_) {
    currentUser = null;
  }
  renderAccount();
}

async function loadDashboard() {
  const dot = byId("service-dot");
  try {
    const data = await getJson("/api/v1/dashboard");
    byId("city-name").textContent = data.city;
    byId("risk-score").textContent = data.risk_score;
    byId("risk-tag").textContent = data.risk_level;
    byId("risk-tag").dataset.level = data.risk_level;
    byId("risk-meter").style.width = `${data.risk_score}%`;
    byId("risk-meter").style.background = data.risk_score >= 60 ? "#c84d4d" : data.risk_score >= 30 ? "#d89a31" : "#17836f";
    document.querySelector(".risk-track").setAttribute("aria-valuenow", data.risk_score);
    byId("open-count").textContent = data.open_reports;
    byId("high-count").textContent = data.high_severity_reports;
    byId("resolved-count").textContent = data.resolved_reports;
    byId("data-label").innerHTML = `<span aria-hidden="true">●</span> ${escapeHtml(data.data_label)}`;
    if (data.privacy) {
      const badge = byId("privacy-badge");
      const label = byId("privacy-status-label");
      const msg = byId("privacy-message");
      const count = byId("privacy-blocks-count");
      const lastEvent = byId("privacy-last-event");
      if (badge) badge.className = `privacy-status-badge status-${escapeHtml(data.privacy.status)}`;
      if (label) label.textContent = data.privacy.status_label;
      if (msg) msg.textContent = data.privacy.message;
      if (count) count.textContent = data.privacy.blocked_preventions_count;
      if (lastEvent) {
        lastEvent.textContent = data.privacy.last_event_at
          ? `Última prevenção: ${formatDate(data.privacy.last_event_at)}`
          : "Nenhum incidente registrado";
      }
    }
    byId("service-status").textContent = "Serviço conectado";
    dot.style.background = "#81d4a9";
    dot.style.boxShadow = "0 0 0 4px rgba(129, 212, 169, .13)";
  } catch (_) {
    byId("service-status").textContent = "API indisponível";
    dot.style.background = "#e27d70";
    dot.style.boxShadow = "0 0 0 4px rgba(226, 125, 112, .14)";
  }
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "data não informada";
  return new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "short" }).format(date);
}

async function loadReports() {
  const list = byId("report-list");
  try {
    const reports = await getJson("/api/v1/reports");
    byId("report-count").textContent = `${reports.length} ${reports.length === 1 ? "relato" : "relatos"}`;
    if (!reports.length) {
      list.innerHTML = '<div class="empty-state"><span class="empty-icon" aria-hidden="true">⌕</span><strong>Nenhum relato por enquanto</strong><span>Quando uma ocorrência for enviada, ela aparecerá aqui.</span></div>';
      return;
    }
    const severityLabels = { high: "Alta", medium: "Média", low: "Baixa" };
    list.innerHTML = reports.map((report) => `
      <article class="report-item"><div><div class="report-title">${escapeHtml(report.category)}${report.demonstrative ? '<span class="demo-badge">DEMO</span>' : ""}</div>
      <div class="report-meta">${escapeHtml(report.neighborhood)} · ${escapeHtml(formatDate(report.created_at))} · ${escapeHtml(report.status === "open" ? "Em aberto" : report.status)}</div></div>
      <span class="severity-badge ${escapeHtml(report.severity)}">${escapeHtml(severityLabels[report.severity] || report.severity)}</span></article>`).join("");
  } catch (_) {
    byId("report-count").textContent = "indisponível";
    list.innerHTML = '<div class="empty-state"><strong>Não foi possível carregar os relatos</strong><span>Tente atualizar os dados em alguns instantes.</span></div>';
  }
}

async function loadWeather() {
  try {
    const weather = await getJson("/api/v1/weather");
    byId("weather-title").textContent = `${Number(weather.precipitation_mm).toFixed(1)} mm de chuva atual`;
    byId("weather-risk").textContent = `Risco ${weather.risk_level}`;
    byId("weather-detail").textContent = weather.forecast_probability_percent == null ? weather.source : `Probabilidade máxima hoje: ${weather.forecast_probability_percent}%`;
    byId("weather-source").textContent = weather.source;
  } catch (_) {
    byId("weather-title").textContent = "Previsão indisponível";
    byId("weather-risk").textContent = "Sem leitura";
    byId("weather-detail").textContent = "Os relatos comunitários continuam disponíveis.";
    byId("weather-source").textContent = "A fonte meteorológica pode estar temporariamente fora do ar.";
  }
}

function setAuthTab(tab) {
  const register = tab === "register";
  byId("login-form").hidden = register;
  byId("register-form").hidden = !register;
  byId("login-tab").setAttribute("aria-selected", String(!register));
  byId("register-tab").setAttribute("aria-selected", String(register));
  byId("auth-feedback").textContent = "";
}

function openAuth(tab = "login") {
  setAuthTab(tab);
  byId("auth-dialog").showModal();
  (tab === "register" ? byId("register-email") : byId("login-email")).focus();
}

async function submitAuth(form, endpoint) {
  const formData = new FormData(form);
  const feedback = byId("auth-feedback");
  feedback.textContent = "Verificando acesso…";
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: formData.get("email"), password: formData.get("password") })
    });
    const result = await response.json();
    if (!response.ok) {
      feedback.textContent = result.message || "Não foi possível entrar. Confira os dados e tente novamente.";
      return;
    }
    currentUser = result;
    renderAccount();
    byId("auth-dialog").close();
    form.reset();
    showToast("Acesso iniciado. Agora você pode registrar uma ocorrência.");
  } catch (_) {
    feedback.textContent = "Não foi possível conectar ao serviço. Tente novamente.";
  }
}

byId("refresh").addEventListener("click", () => Promise.all([loadDashboard(), loadReports(), loadWeather()]));
byId("account-button").addEventListener("click", () => openAuth("login"));
byId("prompt-login").addEventListener("click", () => openAuth("login"));
byId("close-auth").addEventListener("click", () => byId("auth-dialog").close());
byId("login-tab").addEventListener("click", () => setAuthTab("login"));
byId("register-tab").addEventListener("click", () => setAuthTab("register"));
byId("login-form").addEventListener("submit", (event) => { event.preventDefault(); submitAuth(event.currentTarget, "/api/v1/auth/login"); });
byId("register-form").addEventListener("submit", (event) => { event.preventDefault(); submitAuth(event.currentTarget, "/api/v1/auth/register"); });
byId("logout-button").addEventListener("click", async () => {
  await fetch("/api/v1/auth/logout", { method: "POST", credentials: "same-origin" });
  currentUser = null;
  renderAccount();
  showToast("Você saiu da sua conta.");
});

byId("report-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("submit-report");
  const feedback = byId("form-feedback");
  const category = byId("category");
  const neighborhood = byId("neighborhood");
  if (!category.value || !neighborhood.value.trim()) {
    feedback.className = "feedback show error";
    feedback.textContent = "Escolha uma categoria e informe o bairro ou região.";
    (!category.value ? category : neighborhood).focus();
    return;
  }

  button.disabled = true;
  button.innerHTML = "Verificando dados… <span aria-hidden=\"true\">◌</span>";
  feedback.className = "feedback";
  const payload = {
    category: category.value,
    neighborhood: neighborhood.value.trim(),
    details: byId("details").value.trim(),
    severity: document.querySelector('input[name="severity"]:checked').value
  };
  try {
    const response = await fetch("/api/v1/reports", {
      method: "POST", credentials: "same-origin",
      headers: { "content-type": "application/json" }, body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) {
      if (response.status === 401) {
        currentUser = null;
        renderAccount();
        feedback.textContent = "Sua sessão expirou. Entre novamente para enviar o relato.";
      } else {
        feedback.textContent = response.status === 429
          ? `Muitos envios em pouco tempo. Aguarde ${response.headers.get("retry-after") || "um minuto"} segundos antes de tentar novamente.`
          : result.message || "Revise os dados e tente novamente.";
      }
      feedback.className = "feedback show error";
      return;
    }
    feedback.className = "feedback show ok";
    feedback.textContent = result.message;
    byId("report-form").reset();
    await Promise.all([loadDashboard(), loadReports()]);
    showToast("Relato registrado com segurança");
  } catch (_) {
    feedback.className = "feedback show error";
    feedback.textContent = "Não foi possível conectar ao serviço. Tente novamente.";
  } finally {
    button.disabled = false;
    button.innerHTML = "Enviar relato com segurança <span aria-hidden=\"true\">→</span>";
  }
});

Promise.all([loadCurrentUser(), loadDashboard(), loadReports(), loadWeather()]);
