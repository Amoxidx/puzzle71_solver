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
let claimPending = false;
let claimBusyKind = null;
let lastClaimPhase = null;
let lastClaimTxidLogged = null;
let claimAlertsRemaining = null;
let preparedDestination = null;
let lastPreparedTxid = null;
let claimAwaitingOutcome = false;
let claimAwaitingStartTxid = null;
let claimAwaitingPolls = 0;
let claimBusySeenTrue = false;

const CLAIM_INFLIGHT_TEXT = "Vorgang läuft noch – Status wird abgefragt";
const CLAIM_UNKNOWN_TEXT = "Ergebnis unbekannt – bitte Status prüfen und gegebenenfalls erneut versuchen";
const CLAIM_UNKNOWN_CONFIRM_TEXT = "Ergebnis unbekannt – bitte Status prüfen und den Code neu eingeben";
const CLAIM_PREPARE_UNCHANGED_TEXT =
  "Erneute Prüfung ohne Rückmeldung – die angezeigte Zusammenfassung gilt weiter";
const CLAIM_ERROR_TEXT = {
  invalid_address: "Ungültige Bitcoin-Adresse",
  wrong_network: "Adresse gehört nicht zum Bitcoin-Netz",
  unsupported_address_type: "Dieser Adresstyp wird nicht unterstützt",
  destination_is_puzzle_address: "Die Puzzle-Adresse selbst ist nicht erlaubt",
  fee_floor_too_high: "Die Slipstream-Mindestgebühr liegt über dem erlaubten Maximum",
  sources_disagree: "Die UTXO-Quellen stimmen nicht überein",
  network_error: "Netzwerkfehler – bitte erneut versuchen",
  not_prepared: "Zuerst die Adresse prüfen",
  destination_mismatch: "Adresse stimmt nicht mit der geprüften Zusammenfassung überein",
  wrong_code: "Falscher Code",
  locked: "Gesperrt nach 5 Fehlversuchen – Solver neu starten, um einen neuen Code zu erhalten",
  no_code: "Kein Bestätigungscode vorhanden",
  resend_limit_reached: "Kein weiterer Code-Versand möglich",
  invalid_state: "Dieser Schritt ist im aktuellen Zustand nicht möglich",
  balance_below_expected: "Guthaben liegt unter dem erwarteten Minimum",
  summary_changed: "Zusammenfassung hat sich geändert – Adresse erneut prüfen",
  already_submitted_different: "Es liegt bereits eine andere Einreichung vor",
  submission_rejected: "Abgelehnt – neue Vorbereitung möglich",
  submission_unknown: "Einreichung unklar – Status wird weiter abgefragt",
  submission_not_found: "Bei MARA nicht gefunden – gleiche Transaktion erneut senden möglich",
  marker_unreadable: "Markierungsdatei `CLAIM_SUBMITTED.json` unlesbar – bitte von Hand prüfen, bevor erneut gesendet wird",
  storage_error: "Speicherfehler bei der Markierungsdatei",
  code_unavailable: "Code konnte nicht erzeugt werden",
  claim_build_failed: "Transaktion konnte nicht gebaut werden",
  no_claim_available: "Kein Claim verfügbar",
  claim_busy: "Claim-Dienst ist gerade beschäftigt",
};

const CLAIM_FAILED_TEXT = {
  submission_rejected: "Abgelehnt – neue Vorbereitung möglich",
  submission_unknown: "Einreichung unklar – Status wird weiter abgefragt",
  submission_not_found: "Bei MARA nicht gefunden – gleiche Transaktion erneut senden möglich",
  marker_unreadable: "Markierungsdatei `CLAIM_SUBMITTED.json` unlesbar – bitte von Hand prüfen, bevor erneut gesendet wird",
};

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
  byId("btn-claim-prepare").addEventListener("click", prepareClaim);
  byId("btn-claim-confirm").addEventListener("click", confirmClaim);
  byId("btn-claim-resend").addEventListener("click", resendClaimCode);
  byId("claim-destination").addEventListener("blur", hintDestination);
  byId("claim-destination").addEventListener("input", syncConfirmEnabled);
  byId("claim-code").addEventListener("input", syncConfirmEnabled);
  byId("claim-verified-on-device").addEventListener("change", syncConfirmEnabled);

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
  let response;
  try {
    response = await fetch(url, {
      cache: "no-store",
      ...options,
      headers: {
        Accept: "application/json",
        ...(options.headers || {}),
      },
    });
  } catch (error) {
    error.networkFailure = true;
    throw error;
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || `HTTP ${response.status}`);
    error.code = data.error;
    error.remaining_attempts = data.remaining_attempts;
    error.txid = data.txid;
    throw error;
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
  renderClaim(data.claim, data.hit, data.claim_busy);

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

function claimPhase(claim) {
  if (claim == null) return null;
  if (claim === "Idle" || claim === "Locked") return claim;
  if (typeof claim === "object") {
    if (Object.hasOwn(claim, "AwaitingOwner")) return "AwaitingOwner";
    if (Object.hasOwn(claim, "Prepared")) return "Prepared";
    if (Object.hasOwn(claim, "Submitted")) return "Submitted";
    if (Object.hasOwn(claim, "Confirmed")) return "Confirmed";
    if (Object.hasOwn(claim, "Failed")) return "Failed";
  }
  return null;
}

function claimFields(claim) {
  if (!claim || typeof claim !== "object") return {};
  return claim.AwaitingOwner || claim.Prepared || claim.Submitted || claim.Confirmed || claim.Failed || {};
}

function satToBtc(sat) {
  return (Number(sat) / 100_000_000).toFixed(8);
}

function groupInFours(value) {
  const compact = String(value || "").replace(/\s+/g, "");
  const parts = [];
  for (let i = 0; i < compact.length; i += 4) {
    parts.push(compact.slice(i, i + 4));
  }
  return parts.join(" ");
}

function setHidden(id, hidden) {
  byId(id).classList.toggle("hidden", hidden);
}

function claimErrorText(code, remaining) {
  if (!code) return "Unbekannter Fehler";
  const base = CLAIM_ERROR_TEXT[code] || `Unbekannter Fehler (${code})`;
  if (code === "wrong_code" && remaining != null) {
    return `${base}. Noch ${remaining} Versuche`;
  }
  return base;
}

function renderClaim(claim, hit, claimBusy) {
  const panel = byId("claim-panel");
  if (!hit || claim == null) {
    panel.classList.add("hidden");
    lastClaimPhase = null;
    return;
  }
  panel.classList.remove("hidden");
  const phase = claimPhase(claim);
  const fields = claimFields(claim);

  if (claimAwaitingOutcome) {
    claimAwaitingPolls += 1;
    if (claimBusy === true) {
      claimBusySeenTrue = true;
    }
    const currentTxid = phase === "Prepared" && fields.summary
      ? String(fields.summary.txid || "")
      : "";
    const txidChanged = Boolean(claimAwaitingStartTxid)
      && Boolean(currentTxid)
      && currentTxid !== claimAwaitingStartTxid;
    const busyReleased = claimBusy === false
      && (claimBusySeenTrue || claimAwaitingPolls >= 2);
    const phaseChanged = phase !== lastClaimPhase;
    if (phaseChanged || txidChanged || busyReleased) {
      const wasPrepare = claimBusyKind === "prepare";
      const wasConfirm = claimBusyKind === "confirm";
      const inflightTarget = wasPrepare
        ? "claim-destination-error"
        : "claim-confirm-error";
      claimAwaitingOutcome = false;
      claimPending = false;
      claimBusyKind = null;
      claimAwaitingStartTxid = null;
      for (const id of ["claim-destination-error", "claim-confirm-error"]) {
        if (byId(id).textContent === CLAIM_INFLIGHT_TEXT) {
          byId(id).textContent = "";
        }
      }
      const unchangedPreparedPrepare = wasPrepare && phase === "Prepared";
      if (wasConfirm && phaseChanged && phase === "AwaitingOwner") {
        byId("claim-destination-error").textContent = CLAIM_ERROR_TEXT.summary_changed;
      } else if (wasPrepare && phase === "Prepared" && !phaseChanged && !txidChanged) {
        byId("claim-destination-error").textContent = CLAIM_PREPARE_UNCHANGED_TEXT;
      } else if (!phaseChanged && !txidChanged && !unchangedPreparedPrepare) {
        if (wasConfirm) {
          byId("claim-code").value = "";
          byId(inflightTarget).textContent = CLAIM_UNKNOWN_CONFIRM_TEXT;
        } else {
          byId(inflightTarget).textContent = CLAIM_UNKNOWN_TEXT;
        }
      }
    }
  }

  if (phase !== lastClaimPhase) {
    if (phase === "Submitted" || phase === "Confirmed") {
      byId("claim-confirm-error").textContent = "";
      byId("claim-destination-error").textContent = "";
    }
    if (phase !== "Prepared") {
      byId("claim-code").value = "";
      byId("claim-verified-on-device").checked = false;
    }
    lastClaimPhase = phase;
  }

  const showAlert = phase === "Idle" || phase === "AwaitingOwner" || phase === "Prepared" || phase === "Failed";
  const alertEl = byId("claim-alert-status");
  if (showAlert && Object.hasOwn(fields, "alert_sent")) {
    alertEl.textContent = fields.alert_sent
      ? "Code per Telegram gesendet"
      : "Telegram-Versand fehlgeschlagen";
  } else if (showAlert && phase === "Idle") {
    alertEl.textContent = "";
  } else {
    alertEl.textContent = "";
  }
  const resend = byId("btn-claim-resend");
  resend.classList.toggle("hidden", !showAlert || phase === "Idle");
  setHidden("claim-alert-row", !showAlert);
  claimAlertsRemaining = fields.alerts_remaining;

  const showDest = phase === "Idle" || phase === "AwaitingOwner" || phase === "Prepared" || phase === "Failed";
  setHidden("claim-step-destination", !showDest);
  setHidden("claim-step-summary", phase !== "Prepared");
  setHidden("claim-step-confirm", phase !== "Prepared");
  setHidden("claim-step-result", !["Submitted", "Confirmed", "Locked", "Failed"].includes(phase));

  if (phase === "Prepared" && fields.summary) {
    const summary = fields.summary;
    preparedDestination = String(summary.destination || "");
    lastPreparedTxid = String(summary.txid || "");
    const destInput = byId("claim-destination");
    if (!destInput.value.trim() && preparedDestination) {
      destInput.value = preparedDestination;
    }
    byId("claim-summary-destination").textContent = groupInFours(summary.destination);
    byId("claim-summary-inputs").textContent =
      `${summary.input_count} · ${satToBtc(summary.total_input_sat)} BTC`;
    byId("claim-summary-fee").textContent =
      `${formatNumber(summary.fee_sat)} sat · ${formatOne(summary.effective_fee_rate_sat_vb)} sat/vB`;
    byId("claim-summary-payout").textContent = `${satToBtc(summary.output_sat)} BTC`;
    byId("claim-summary-dust").textContent =
      `${summary.excluded_dust_count} · ${formatNumber(summary.excluded_dust_sat)} sat`;
  } else if (phase !== "Prepared") {
    preparedDestination = null;
    lastPreparedTxid = null;
  }

  if (phase === "Prepared" && typeof fields.attempts_remaining === "number") {
    byId("claim-attempts").textContent = `Verbleibende Code-Versuche: ${fields.attempts_remaining}`;
  } else {
    byId("claim-attempts").textContent = "";
  }

  const resultStatus = byId("claim-result-status");
  const resultTxid = byId("claim-result-txid");
  const resultDetail = byId("claim-result-detail");
  resultTxid.textContent = "";
  resultDetail.textContent = "";
  if (phase === "Submitted") {
    resultStatus.textContent = "Eingereicht";
    resultTxid.textContent = fields.txid || "";
    resultDetail.textContent =
      "Warte auf Bestätigung im nächsten MARA-Block (≈5 % Hashrate, im Mittel etwa 3 Stunden)";
    if (fields.txid && fields.txid !== lastClaimTxidLogged) {
      lastClaimTxidLogged = fields.txid;
      addLog(`[CLAIM] Eingereicht: ${fields.txid}`, "success");
    }
  } else if (phase === "Confirmed") {
    resultStatus.textContent = `Bestätigt in Block ${fields.block_height}`;
    resultTxid.textContent = fields.txid || "";
    resultDetail.textContent = "";
  } else if (phase === "Locked") {
    resultStatus.textContent = "Gesperrt nach 5 Fehlversuchen – Solver neu starten, um einen neuen Code zu erhalten";
    resultTxid.textContent = "";
    resultDetail.textContent = "";
  } else if (phase === "Failed") {
    resultStatus.textContent = "Fehlgeschlagen";
    resultTxid.textContent = "";
    resultDetail.textContent = CLAIM_FAILED_TEXT[fields.reason]
      || CLAIM_ERROR_TEXT[fields.reason]
      || `Unbekannter Fehler (${fields.reason || "?"})`;
  } else {
    resultStatus.textContent = "";
  }

  syncClaimButtons();
}

function normalizeDestination(value) {
  const trimmed = String(value || "").trim();
  if (trimmed.toLowerCase().startsWith("bc1")) {
    return trimmed.toLowerCase();
  }
  return trimmed;
}

function destinationsMatch(left, right) {
  return normalizeDestination(left) === normalizeDestination(right);
}

function destinationEditedAfterPrepare() {
  if (lastClaimPhase !== "Prepared" || !preparedDestination) return false;
  return !destinationsMatch(byId("claim-destination").value, preparedDestination);
}

function syncDestinationMismatch() {
  const mismatch = destinationEditedAfterPrepare();
  byId("claim-destination-mismatch").textContent = mismatch
    ? "Adresse wurde nach dem Prüfen geändert – bitte erneut prüfen"
    : "";
  return mismatch;
}

function syncConfirmEnabled() {
  const prepared = lastClaimPhase === "Prepared";
  const checked = byId("claim-verified-on-device").checked;
  const six = /^\d{6}$/.test(byId("claim-code").value.trim());
  const mismatch = syncDestinationMismatch();
  byId("btn-claim-confirm").disabled = claimPending || !prepared || !checked || !six || mismatch;
}

function syncClaimButtons() {
  const prepare = byId("btn-claim-prepare");
  const confirm = byId("btn-claim-confirm");
  const resend = byId("btn-claim-resend");
  prepare.disabled = claimPending;
  prepare.textContent = claimBusyKind === "prepare" ? "Prüfe …" : "Adresse prüfen";
  resend.disabled = claimPending || (claimAlertsRemaining != null && claimAlertsRemaining <= 0);
  resend.textContent = claimBusyKind === "resend" ? "Sende …" : "Neuen Code senden";
  confirm.textContent = claimBusyKind === "confirm" ? "Sende …" : "Transaktion an MARA Slipstream senden";
  if (claimPending) {
    confirm.disabled = true;
  } else {
    syncConfirmEnabled();
  }
}

function hintDestination() {
  const value = byId("claim-destination").value.trim();
  const error = byId("claim-destination-error");
  if (!value) return;
  const looksValid = value.length >= 26 && value.length <= 90 && /^[A-Za-z0-9]+$/.test(value);
  if (!looksValid) {
    if (!error.textContent || error.textContent.startsWith("Hinweis:")) {
      error.textContent = "Hinweis: Bitcoin-Adressen sind 26–90 Zeichen lang und enthalten nur Buchstaben und Ziffern.";
    }
  } else if (error.textContent.startsWith("Hinweis:")) {
    error.textContent = "";
  }
}

async function withClaimAction(kind, action, errorTarget) {
  if (claimPending) return;
  claimPending = true;
  claimBusyKind = kind;
  syncClaimButtons();
  try {
    await action();
  } catch (error) {
    if ((kind === "prepare" || kind === "confirm") && error.networkFailure) {
      claimAwaitingOutcome = true;
      claimAwaitingPolls = 0;
      claimBusySeenTrue = false;
      claimAwaitingStartTxid = lastPreparedTxid;
      byId(errorTarget).textContent = CLAIM_INFLIGHT_TEXT;
    } else {
      const message = claimErrorText(error.code || error.message, error.remaining_attempts);
      byId(errorTarget).textContent = message;
      if (kind === "confirm") {
        byId("claim-code").value = "";
      }
    }
  } finally {
    if (!claimAwaitingOutcome) {
      claimPending = false;
      claimBusyKind = null;
      syncClaimButtons();
    }
    scheduleStatusPoll(0);
  }
}

function clearClaimActionErrors() {
  byId("claim-destination-error").textContent = "";
  byId("claim-confirm-error").textContent = "";
}

function prepareClaim() {
  clearClaimActionErrors();
  const destination = byId("claim-destination").value.trim();
  return withClaimAction("prepare", async () => {
    const result = await fetchJson("/api/claim/prepare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ destination }),
    });
    if (result.summary && result.summary.destination) {
      byId("claim-destination").value = result.summary.destination;
      preparedDestination = result.summary.destination;
    }
    addLog("[CLAIM] Adresse geprüft", "success");
  }, "claim-destination-error");
}

function confirmClaim() {
  clearClaimActionErrors();
  if (!preparedDestination || destinationEditedAfterPrepare()) return;
  const destination = preparedDestination;
  const code = byId("claim-code").value.trim();
  return withClaimAction("confirm", async () => {
    const result = await fetchJson("/api/claim/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ destination, code }),
    });
    byId("claim-code").value = "";
    if (result.txid) {
      addLog(`[CLAIM] Eingereicht: ${result.txid}`, "success");
      lastClaimTxidLogged = result.txid;
    }
  }, "claim-confirm-error");
}

function resendClaimCode() {
  clearClaimActionErrors();
  return withClaimAction("resend", async () => {
    await fetchJson("/api/claim/resend-code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    addLog("[CLAIM] Neuen Code angefordert", "info");
  }, "claim-destination-error");
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
