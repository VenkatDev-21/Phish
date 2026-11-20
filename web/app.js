const state = {
  appUrl: "",
  busy: false,
};

const statusChip = document.querySelector("[data-status-chip]");
const statusText = document.querySelector("[data-status-text]");
const form = document.querySelector("[data-scan-form]");
const input = document.getElementById("url-input");
const clearButton = document.querySelector("[data-clear]");
const hint = document.querySelector("[data-scan-hint]");
const submit = document.querySelector("[data-submit]");
const submitLabel = document.querySelector("[data-submit-label]");
const errorBox = document.querySelector("[data-error]");
const resultBox = document.querySelector("[data-result]");
const badge = document.querySelector("[data-result-badge]");
const resultTitle = document.querySelector("[data-result-title]");
const resultUrl = document.querySelector("[data-result-url]");
const resultProbability = document.querySelector("[data-result-probability]");
const meter = document.querySelector("[data-meter]");
const meterBar = document.querySelector("[data-meter-bar]");
const featureChips = document.querySelector("[data-result-features]");
const resultNote = document.querySelector("[data-result-note]");
const signalValue = document.querySelector("[data-signal-value]");
const signalBar = document.querySelector("[data-signal-bar]");

function setStatus(online, message) {
  if (!statusChip) return;
  statusChip.classList.toggle("is-online", Boolean(online));
  statusChip.classList.toggle("is-offline", online === false);
  if (statusText) statusText.textContent = message;
}

function applyAppLinks() {
  if (!state.appUrl) return;
  document.querySelectorAll("[data-app-link]").forEach((link) => {
    const path = link.dataset.appPath || "";
    link.href = `${state.appUrl}${path}`;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
  });
}

async function loadHealth() {
  try {
    const response = await fetch("/api/health", {
      headers: { Accept: "application/json" },
    });
    const body = await response.json();
    state.appUrl = (body.appUrl || "").replace(/\/$/, "");
    applyAppLinks();
    if (!response.ok || !body.online) {
      throw new Error(body.error || "The demo API is not reachable.");
    }
    setStatus(true, `${body.environment || "hosted"} · API online`);
  } catch {
    setStatus(false, "Demo API offline");
    if (hint) hint.textContent = "Scans are disabled until the API is reachable";
  }
}

function showError(message) {
  if (!errorBox) return;
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function clearError() {
  if (errorBox) errorBox.hidden = true;
}

function setBusy(busy) {
  state.busy = busy;
  if (!submit) return;
  submit.disabled = busy;
  submitLabel.textContent = busy ? "Analyzing…" : "Analyze URL";
}

function renderResult(report) {
  if (!resultBox) return;
  const dangerous = report.result === "PHISHING";
  const probability = Number(report.probability) || 0;

  badge.textContent = dangerous ? "×" : "✓";
  badge.classList.toggle("is-danger", dangerous);
  badge.classList.toggle("is-safe", !dangerous);

  resultTitle.textContent = `${report.result} · ${report.risk_level} risk`;
  resultTitle.classList.toggle("is-danger", dangerous);
  resultTitle.classList.toggle("is-safe", !dangerous);

  resultUrl.textContent = report.url;
  resultProbability.textContent = `${probability.toFixed(2)}%`;

  meter.classList.toggle("is-danger", dangerous);
  meter.setAttribute("aria-valuenow", String(probability));
  meterBar.style.width = `${Math.max(2, Math.min(100, probability))}%`;

  featureChips.replaceChildren();
  Object.entries(report.features || {}).forEach(([key, value]) => {
    const chip = document.createElement("span");
    chip.textContent = `${key.replace(/_/g, " ")}: ${value}`;
    featureChips.append(chip);
  });

  resultNote.textContent =
    report.disclaimer ||
    "Structural model output only. A low score is not proof of safety.";

  if (signalValue) signalValue.textContent = `${probability.toFixed(1)}%`;
  if (signalBar) signalBar.style.width = `${Math.max(4, Math.min(100, probability))}%`;

  resultBox.hidden = false;
  resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function updateHint() {
  const value = input.value.trim();
  if (clearButton) clearButton.hidden = !value;
  if (!hint || state.busy) return;
  if (!value) {
    hint.textContent = "Ready when you are";
    return;
  }
  try {
    const parsed = new URL(value);
    hint.textContent =
      parsed.protocol === "https:" ? "HTTPS link" : "HTTP link";
  } catch {
    hint.textContent = "Needs http:// or https://";
  }
}

if (input) {
  input.addEventListener("input", updateHint);
  input.addEventListener("blur", () => {
    const value = input.value.trim();
    if (!value || /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return;
    if (!/^[\w.-]+\.[a-z]{2,}/i.test(value)) return;
    input.value = `https://${value}`;
    updateHint();
  });
}

if (clearButton) {
  clearButton.addEventListener("click", () => {
    input.value = "";
    updateHint();
    input.focus();
  });
}

document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.sample;
    updateHint();
    input.focus();
  });
});

if (form) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.busy) return;
    const url = input.value.trim();
    if (!url) {
      showError("Enter a URL before scanning.");
      input.focus();
      return;
    }
    clearError();
    setBusy(true);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.error || `The API returned HTTP ${response.status}.`);
      }
      renderResult(body);
    } catch (error) {
      showError(error.message || "The scan could not be completed.");
      setStatus(false, "Demo API unreachable");
    } finally {
      setBusy(false);
    }
  });
}

loadHealth();
updateHint();
