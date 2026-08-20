// Bitcoin Puzzle #71 Solver Control Center — local client

"use strict";

let isRunning = false;
let currentMode = "auto";
let electricityRate = 0.34;
let consecutivePollFailures = 0;
let pollTimer = null;
let lastHitTimestamp = null;
let lastError = null;
let actionPending = false;

const RANGE_SIZE = 1n << 70n;
const RANGE_SIZE_NUMBER = Number(RANGE_SIZE);
const MODE_LABELS = {
  eco: "ECO",
  balanced: "BALANCED",
  high: "HIGH",
  auto: "AUTO",
  full: "MAX",
};

const ICON_PLAY = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="6 3 20 12 6 21 6 3"></polygon></svg>';
const ICON_STOP = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="1"></rect></svg>';

const byId = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  byId("btn-toggle-run").addEventListener("click", toggleSolver);
  byId("btn-selftest").addEventListener("click", runSelfTest);
  byId("input-eur-kwh").addEventListener("change", (event) => {
    updateElectricityRate(event.target.value);
  });
  document.querySelectorAll(".btn-mode").forEach((button) => {
    button.addEventListener("click", () => setMode(button.dataset.mode));
  });

  const initialLogs = document.querySelectorAll("#log-container .log-entry").length;
  byId("log-count").textContent = `${initialLogs} ${initialLogs === 1 ? "Eintrag" : "Einträge"}`;
  addLog("[INIT] Control Center verbindet sich mit dem lokalen Backend.", "info");
  scheduleStatusPoll(0);
});

function scheduleStatusPoll(delay = 750) {
  window.clearTimeout(pollTimer);
  pollTimer = window.setTimeout(fetchStatus, delay);
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return data;
}

async function fetchStatus() {
  try {
    const data = await fetchJson("/api/status");
    consecutivePollFailures = 0;
    updateUI(data);
  } catch (error) {
    consecutivePollFailures += 1;
    if (consecutivePollFailures === 3) {
      setStatus("offline", "VERBINDUNG GETRENNT");
      addLog(`[VERBINDUNG] Status nicht erreichbar: ${error.message}`, "warn");
    }
  } finally {
    scheduleStatusPoll();
  }
}

function updateUI(data) {
  isRunning = Boolean(data.is_running);
  currentMode = String(data.mode || "auto").toLowerCase();
  const dutyLimit = clampNumber(data.target_gpu_duty_pct, 0, 90);

  if (data.last_error) {
    setStatus("error", "FEHLER — NEUSTART NÖTIG");
  } else if (data.hit) {
    setStatus("hit", "TREFFER — SUCHE BEENDET");
  } else if (isRunning) {
    setStatus("running", "AKTIV AM SUCHEN");
  } else {
    setStatus("paused", "PAUSIERT");
  }
  byId("status-mode").textContent = `${MODE_LABELS[currentMode] || currentMode.toUpperCase()} · LIMIT ${formatOne(dutyLimit)}%`;

  const toggle = byId("btn-toggle-run");
  toggle.className = isRunning ? "btn btn-danger" : "btn btn-primary";
  byId("btn-run-icon").innerHTML = isRunning ? ICON_STOP : ICON_PLAY;
  byId("btn-run-label").textContent = isRunning ? "Suche pausieren" : "Suche starten";
  toggle.disabled = actionPending || Boolean(data.hit) || Boolean(data.last_error);

  document.querySelectorAll(".btn-mode").forEach((button) => {
    const selected = button.dataset.mode === currentMode;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
    button.disabled = actionPending;
  });

  const currentSpeed = finiteNumber(data.current_keys_per_sec);
  const averageSpeed = finiteNumber(data.avg_keys_per_sec);
  byId("val-speed-mkeys").textContent = (currentSpeed / 1_000_000).toFixed(2);
  byId("val-speed-current").textContent = `${formatNumber(Math.round(currentSpeed))} keys/s`;
  byId("val-speed-avg").textContent = `${formatNumber(Math.round(averageSpeed))} keys/s`;

  const watts = finiteNumber(data.estimated_package_power_watts);
  byId("val-power-watts").textContent = watts.toFixed(1);
  const keysPerJoule = watts > 0 ? currentSpeed / watts : 0;
  byId("val-keys-per-joule").textContent = `${(keysPerJoule / 1_000_000).toFixed(2)} Mkeys/Joule`;
  byId("val-keys-per-kwh").textContent = `${(keysPerJoule * 3_600_000 / 1_000_000_000).toFixed(2)} Bkeys/kWh`;

  byId("val-soc-temp").textContent = finiteNumber(data.estimated_soc_temp_celsius).toFixed(1);
  byId("val-cpu-load").textContent = `${finiteNumber(data.process_cpu_load_pct).toFixed(1)}%`;
  byId("val-runtime").textContent = formatTime(data.runtime_secs);
  byId("val-gpu-duty").textContent = `${measuredDuty(data).toFixed(1)}% (Limit ${formatOne(dutyLimit)}%)`;

  const totalKeys = parseNonNegativeBigInt(data.total_keys_tested);
  byId("val-total-keys").textContent = formatBigInt(totalKeys);
  byId("val-total-blocks").textContent = formatNumber(finiteNumber(data.total_blocks_tested));
  const coverage = Math.min(Number(totalKeys) / RANGE_SIZE_NUMBER, 1);
  const coveragePct = coverage * 100;
  byId("val-coverage-pct").textContent = `${coveragePct.toFixed(12)}%`;
  byId("coverage-meter-fill").style.transform = `scaleX(${coverage})`;
  byId("coverage-meter").setAttribute("aria-valuenow", String(coveragePct));
  byId("val-checkpoint").textContent = formatUnixTimestamp(data.checkpoint_saved_timestamp, "Noch nicht gespeichert");

  const runtime = finiteNumber(data.runtime_secs);
  const kwhConsumed = watts * runtime / 3_600_000;
  const dailyCost = watts * 24 / 1000 * electricityRate;
  byId("val-cost-start").textContent = `${(kwhConsumed * electricityRate).toFixed(4)} €`;
  byId("val-cost-day").textContent = `${dailyCost.toFixed(2)} €`;
  byId("val-cost-month").textContent = `${(dailyCost * 30.416).toFixed(2)} €`;
  byId("val-cost-year").textContent = `${(dailyCost * 365.25).toFixed(2)} €`;

  renderOdds(Math.max(averageSpeed, currentSpeed, 0));
  renderHit(data.hit);

  if (data.last_error && data.last_error !== lastError) {
    lastError = data.last_error;
    addLog(`[SOLVER-FEHLER] ${data.last_error}`, "warn");
  }
}

function setStatus(kind, text) {
  byId("status-pill").className = `status-pill status-${kind}`;
  byId("status-text").textContent = text;
}

function measuredDuty(data) {
  const active = finiteNumber(data.last_gpu_active_ms);
  const idle = finiteNumber(data.last_throttle_sleep_ms);
  return active + idle > 0 ? active / (active + idle) * 100 : 0;
}

function renderHit(hit) {
  if (!hit) return;
  byId("hit-alert").classList.remove("hidden");
  byId("hit-address").textContent = hit.bitcoin_address;
  byId("hit-filename").textContent = hit.saved_filename;
  byId("hit-timestamp").textContent = formatUnixTimestamp(hit.timestamp_unix, "Unbekannt");
  if (hit.timestamp_unix !== lastHitTimestamp) {
    lastHitTimestamp = hit.timestamp_unix;
    addLog(`[TREFFER] Puzzle #71 verifiziert; Private Key nur lokal in ${hit.saved_filename} gespeichert.`, "hit");
  }
}

function renderOdds(rate) {
  const horizons = [3600, 86400, 86400 * 30, 86400 * 365.25];
  const ids = ["1h", "24h", "30d", "1y"];
  horizons.forEach((seconds, index) => {
    const probability = Math.min(rate * seconds / RANGE_SIZE_NUMBER, 1);
    byId(`val-odds-${ids[index]}-pct`).textContent = `${(probability * 100).toExponential(2)}%`;
    byId(`val-odds-${ids[index]}-ratio`).textContent = probability > 0
      ? `1 zu ${formatRatio(1 / probability)}`
      : "Keine Rate gemessen";
  });
}

async function withAction(action) {
  if (actionPending) return;
  actionPending = true;
  setControlsDisabled(true);
  try {
    await action();
  } catch (error) {
    addLog(`[FEHLER] ${error.message}`, "warn");
  } finally {
    actionPending = false;
    setControlsDisabled(false);
    scheduleStatusPoll(0);
  }
}

function toggleSolver() {
  return withAction(async () => {
    const wasRunning = isRunning;
    const result = await fetchJson(wasRunning ? "/api/stop" : "/api/start", { method: "POST" });
    addLog(wasRunning
      ? "[AKTION] Pause angefordert; der Checkpoint wird nach dem laufenden GPU-Dispatch geschrieben."
      : "[AKTION] Suche gestartet.", "info");
    return result;
  });
}

function setMode(mode) {
  if (!Object.hasOwn(MODE_LABELS, mode)) return Promise.resolve();
  return withAction(async () => {
    await fetchJson("/api/mode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode }),
    });
    addLog(`[POWER] Modus ${MODE_LABELS[mode]} angefordert.`, "info");
  });
}

function runSelfTest() {
  return withAction(async () => {
    byId("btn-selftest").disabled = true;
    addLog("[TEST] Starte den lokalen 24-Bit CPU-Selbsttest.", "info");
    const data = await fetchJson("/api/selftest", { method: "POST" });
    if (!data.success) throw new Error(data.error || "Selbsttest fehlgeschlagen");
    addLog(`[TEST ERFOLG] ${data.engine}-Selbsttest in ${finiteNumber(data.elapsed_secs).toFixed(3)} s (${formatNumber(Math.round(finiteNumber(data.keys_per_sec)))} keys/s).`, "success");
  });
}

function updateElectricityRate(value) {
  const parsed = Number.parseFloat(value);
  if (Number.isFinite(parsed) && parsed > 0) {
    electricityRate = parsed;
    addLog(`[KONFIGURATION] Strompreis auf ${electricityRate.toFixed(2)} €/kWh gesetzt.`, "info");
    scheduleStatusPoll(0);
  }
}

function setControlsDisabled(disabled) {
  byId("btn-toggle-run").disabled = disabled;
  byId("btn-selftest").disabled = disabled;
  document.querySelectorAll(".btn-mode").forEach((button) => { button.disabled = disabled; });
}

function parseNonNegativeBigInt(value) {
  try {
    const parsed = BigInt(value ?? 0);
    return parsed >= 0n ? parsed : 0n;
  } catch (_) {
    return 0n;
  }
}

function finiteNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function clampNumber(value, min, max) {
  return Math.min(Math.max(finiteNumber(value), min), max);
}

function formatNumber(value) {
  return finiteNumber(value).toLocaleString("de-DE", { maximumFractionDigits: 0 });
}

function formatBigInt(value) {
  return value.toLocaleString("de-DE");
}

function formatOne(value) {
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

function formatTime(seconds) {
  const total = Math.max(0, Math.floor(finiteNumber(seconds)));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
}

function formatUnixTimestamp(seconds, fallback) {
  const numeric = finiteNumber(seconds);
  if (numeric <= 0) return fallback;
  return new Date(numeric * 1000).toLocaleString("de-DE");
}

function formatRatio(value) {
  if (!Number.isFinite(value)) return "∞";
  if (value >= 1e15) return `${(value / 1e15).toFixed(1)} Brd.`;
  if (value >= 1e12) return `${(value / 1e12).toFixed(1)} Bio.`;
  if (value >= 1e9) return `${(value / 1e9).toFixed(1)} Mrd.`;
  if (value >= 1e6) return `${(value / 1e6).toFixed(1)} Mio.`;
  if (value >= 1e3) return `${(value / 1e3).toFixed(1)} Tsd.`;
  return Math.round(value).toLocaleString("de-DE");
}

function addLog(message, type = "info") {
  const entry = document.createElement("div");
  entry.className = `log-entry log-${type}`;
  entry.textContent = `[${new Date().toLocaleTimeString("de-DE")}] ${message}`;
  byId("log-container").appendChild(entry);
  byId("log-container").scrollTop = byId("log-container").scrollHeight;
  const count = document.querySelectorAll("#log-container .log-entry").length;
  byId("log-count").textContent = `${count} ${count === 1 ? "Eintrag" : "Einträge"}`;
}
