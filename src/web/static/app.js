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
let preparedDestination = null;
let lastPreparedTxid = null;
let preparedRenderValid = false;
let preparedEdited = false;
let previewNeedsRecheck = false;
let claimStoragePending = false;
let claimServerBusy = false;
let claimRevision = 0;
let claimAwaitingOutcome = false;
let claimAwaitingPolls = 0;

const CLAIM_INFLIGHT_TEXT = "Vorgang läuft noch – Status wird abgefragt";
const CLAIM_UNKNOWN_TEXT = "Ergebnis unklar – Status prüfen und die Adresse vor einem weiteren Sendeversuch erneut prüfen";
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
  prepared_txid_mismatch: "Vorschau ist veraltet – Adresse erneut prüfen",
  invalid_state: "Dieser Schritt ist im aktuellen Zustand nicht möglich",
  balance_below_expected: "Guthaben liegt unter dem erwarteten Minimum",
  summary_changed: "Zusammenfassung hat sich geändert – Adresse erneut prüfen",
  already_submitted_different: "Es liegt bereits eine andere Einreichung vor",
  submission_rejected: "Abgelehnt – neue Vorbereitung möglich",
  submission_unknown: "Einreichung unklar – Status wird weiter abgefragt",
  submission_not_found: "Bei MARA nicht gefunden – gleiche Transaktion erneut senden möglich",
  marker_unreadable: "Markierungsdatei `CLAIM_SUBMITTED.json` unlesbar – bitte von Hand prüfen, bevor erneut gesendet wird",
  storage_error: "Speicherfehler bei der Markierungsdatei",
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
  byId("claim-destination").addEventListener("blur", hintDestination);
  byId("claim-destination").addEventListener("input", () => {
    if (preparedDestination) {
      preparedEdited = true;
      previewNeedsRecheck = false;
      preparedRenderValid = false;
      setHidden("claim-step-summary", true);
      setHidden("claim-step-confirm", true);
    }
    syncClaimButtons();
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
    error.txid = data.txid;
    throw error;
  }
  return data;
}

async function fetchStatus() {
  const revision = claimRevision;
  try {
    const data = await fetchJson("/api/status");
    consecutivePollFailures = 0;
    updateUI(data, revision);
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

function updateUI(data, revision = claimRevision) {
  isRunning = Boolean(data.is_running);
  currentMode = String(data.mode || "auto").toLowerCase();
  const dutyLimit = clampNumber(data.target_gpu_duty_pct, 0, 90);

  if (data.hit && data.hit.storage_pending) {
    setStatus("hit", "Treffer bestätigt – Speicherung wird wiederholt");
  } else if (data.last_error) {
    setStatus("error", "FEHLER — NEUSTART NÖTIG");
  } else if (data.hit) {
    setStatus("hit", "TREFFER — SUCHE BEENDET");
  } else if (isRunning) {
    setStatus("running", "AKTIV AM SUCHEN");
  } else {
    setStatus("paused", "PAUSIERT");
  }
  setTextIfChanged(byId("status-mode"), `${MODE_LABELS[currentMode] || currentMode.toUpperCase()} · LIMIT ${formatOne(dutyLimit)}%`);

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
  const progressAvailable = data.progress_available !== false;
  setTextIfChanged(byId("val-speed-avg"), progressAvailable
    ? `${formatNumber(Math.round(averageSpeed))} keys/s`
    : "Nicht verfügbar");

  const watts = finiteNumber(data.estimated_package_power_watts);
  const hasDispatchSample = finiteNumber(data.last_gpu_active_ms) + finiteNumber(data.last_throttle_sleep_ms) > 0;
  setTextIfChanged(byId("val-power-watts"), hasDispatchSample ? watts.toFixed(1) : "Nicht verfügbar");
  const keysPerJoule = watts > 0 ? currentSpeed / watts : 0;
  setTextIfChanged(byId("val-keys-per-joule"), hasDispatchSample ? `${(keysPerJoule / 1_000_000).toFixed(2)} Mkeys/Joule` : "Nicht verfügbar");
  setTextIfChanged(byId("val-keys-per-kwh"), hasDispatchSample ? `${(keysPerJoule * 3_600_000 / 1_000_000_000).toFixed(2)} Bkeys/kWh` : "Nicht verfügbar");

  setTextIfChanged(byId("val-soc-temp"), hasDispatchSample ? finiteNumber(data.estimated_soc_temp_celsius).toFixed(1) : "Nicht verfügbar");
  byId("val-cpu-load").textContent = `${finiteNumber(data.process_cpu_load_pct).toFixed(1)}%`;
  setTextIfChanged(byId("val-runtime"), progressAvailable ? formatTime(data.runtime_secs) : "Nicht verfügbar");
  byId("val-gpu-duty").textContent = `${measuredDuty(data).toFixed(1)}% (Limit ${formatOne(dutyLimit)}%)`;

  const totalKeys = progressAvailable ? parseNonNegativeBigInt(data.total_keys_tested) : 0n;
  setTextIfChanged(byId("val-total-keys"), progressAvailable ? formatBigInt(totalKeys) : "Nicht verfügbar");
  setTextIfChanged(byId("val-total-blocks"), progressAvailable ? formatNumber(finiteNumber(data.total_blocks_tested)) : "Nicht verfügbar");
  const coverage = progressAvailable ? Math.min(Number(totalKeys) / RANGE_SIZE_NUMBER, 1) : 0;
  const coveragePct = coverage * 100;
  setTextIfChanged(byId("val-coverage-pct"), progressAvailable ? `${coveragePct.toFixed(12)}%` : "Nicht verfügbar");
  byId("coverage-meter-fill").style.transform = `scaleX(${coverage})`;
  byId("coverage-meter").setAttribute("aria-valuenow", String(coveragePct));
  byId("coverage-meter").setAttribute("aria-valuetext", progressAvailable
    ? `Gezählte Historie: ${coveragePct.toFixed(12)} Prozent`
    : "Suchhistorie nicht verfügbar");
  setTextIfChanged(byId("val-checkpoint"), progressAvailable
    ? formatUnixTimestamp(data.checkpoint_saved_timestamp, "Noch nicht gespeichert")
    : "Nicht verfügbar");
  setTextIfChanged(byId("history-note"), progressAvailable
    ? "Übernommene Einträge wurden nicht automatisch rückwirkend nachgeprüft."
    : "Suchhistorie beim Trefferstart nicht verfügbar; der leere Wert bedeutet nicht null.");

  const runtime = finiteNumber(data.runtime_secs);
  const kwhProjected = watts * runtime / 3_600_000;
  const dailyCost = watts * 24 / 1000 * electricityRate;
  const euro4 = new Intl.NumberFormat("de-DE", { minimumFractionDigits: 4, maximumFractionDigits: 4 });
  const euro2 = new Intl.NumberFormat("de-DE", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  setTextIfChanged(byId("val-cost-start"), progressAvailable && hasDispatchSample ? `${euro4.format(kwhProjected * electricityRate)} €` : "Nicht verfügbar");
  setTextIfChanged(byId("val-cost-day"), hasDispatchSample ? `${euro2.format(dailyCost)} €` : "Nicht verfügbar");
  setTextIfChanged(byId("val-cost-month"), hasDispatchSample ? `${euro2.format(dailyCost * 30.416)} €` : "Nicht verfügbar");
  setTextIfChanged(byId("val-cost-year"), hasDispatchSample ? `${euro2.format(dailyCost * 365.25)} €` : "Nicht verfügbar");

  setTextIfChanged(byId("model-state-note"), !hasDispatchSample
    ? "Modellwerte noch nicht verfügbar; ein GPU-Dispatch liegt noch nicht vor."
    : isRunning
      ? "Temperatur geschätzt; Prozess-CPU ist ein Prozesswert."
      : "Temperaturmodell zeigt den letzten Dispatch; Prozess-CPU ist ein Prozesswert.");
  const oddsRate = isRunning ? Math.max(averageSpeed, currentSpeed, 0) : 0;
  setTextIfChanged(byId("odds-note"), isRunning
    ? "Projektion bei aktueller gemessener Rate."
    : "Suche pausiert: aktuell keine Trefferchance; Projektion wird nicht fortgeschrieben.");
  renderOdds(oddsRate);
  renderHit(data.hit);
  claimStoragePending = Boolean(data.hit && data.hit.storage_pending);
  if ((revision === claimRevision && (!claimPending || claimAwaitingOutcome)) || claimStoragePending) {
    renderClaim(data.claim, data.hit, data.claim_busy, data.claim_status_details);
  }

  if (data.last_error && data.last_error !== lastError) {
    lastError = data.last_error;
    addLog(`[SOLVER-FEHLER] ${data.last_error}`, "warn");
  }
}

function setStatus(kind, text) {
  setClassIfChanged(byId("status-pill"), `status-pill status-${kind}`);
  setTextIfChanged(byId("status-text"), text);
}

function setClassIfChanged(element, value) {
  if (element && element.className !== value) element.className = value;
}

function setTextIfChanged(element, value) {
  if (element && element.textContent !== value) element.textContent = value;
}

function measuredDuty(data) {
  const active = finiteNumber(data.last_gpu_active_ms);
  const idle = finiteNumber(data.last_throttle_sleep_ms);
  return active + idle > 0 ? active / (active + idle) * 100 : 0;
}

function renderHit(hit) {
  if (!hit) return;
  const pending = Boolean(hit.storage_pending);
  byId("hit-alert").classList.remove("hidden");
  setTextIfChanged(byId("hit-title"), pending
    ? "Treffer bestätigt – Speicherung wird wiederholt"
    : "PUZZLE #71 TREFFER VERIFIZIERT");
  setTextIfChanged(byId("hit-subtitle"), pending
    ? "Der Treffer ist auf der CPU verifiziert. Die lokale Speicherung wird erneut versucht; den Prozess weiterlaufen lassen. Die Auszahlung bleibt bis zum Speichern gesperrt."
    : "Der Treffer wurde auf der CPU verifiziert. Der Private Key ist ausschließlich in der lokalen Datei gespeichert und wird niemals über die Web-API übertragen.");
  setTextIfChanged(byId("hit-address"), hit.bitcoin_address);
  setTextIfChanged(byId("hit-filename"), pending ? "Speicherung ausstehend" : hit.saved_filename);
  setTextIfChanged(byId("hit-timestamp"), formatUnixTimestamp(hit.timestamp_unix, "Unbekannt"));
  const verificationStatus = byId("hit-verification-status");
  verificationStatus.classList.toggle("hit-badge-pending", pending);
  verificationStatus.classList.toggle("hit-badge-success", !pending);
  setTextIfChanged(verificationStatus, pending
    ? "CPU-VERIFIZIERT · SPEICHERUNG AUSSTEHEND"
    : "CPU-VERIFIZIERT · DATEIRECHTE 0600");
  const identity = `${hit.timestamp_unix}:${pending}`;
  if (identity !== lastHitTimestamp) {
    lastHitTimestamp = identity;
    addLog(pending
      ? "[TREFFER] Treffer bestätigt – Speicherung wird wiederholt."
      : `[TREFFER] Puzzle #71 verifiziert; Private Key nur lokal in ${hit.saved_filename} gespeichert.`, "hit");
  }
}

function claimPhase(claim) {
  if (claim === "Idle" || claim === "AwaitingOwner") return claim;
  if (claim && typeof claim === "object") {
    return ["Prepared", "Submitted", "Confirmed", "Failed"].find((key) => Object.hasOwn(claim, key)) || null;
  }
  return null;
}

function claimFields(claim) {
  const phase = claimPhase(claim);
  return claim && typeof claim === "object" ? claim[phase] || {} : {};
}

function setHidden(id, hidden) {
  byId(id).classList.toggle("hidden", hidden);
}

function claimErrorText(code) {
  return CLAIM_ERROR_TEXT[code] || `Unbekannter Fehler (${code || "?"})`;
}

function normalizeDestination(value) {
  const trimmed = String(value || "").trim();
  return /^(bc1|tb1|bcrt1)/i.test(trimmed) ? trimmed.toLowerCase() : trimmed;
}

function destinationEditedAfterPrepare() {
  return preparedEdited || Boolean(normalizeDestination(byId("claim-destination").value)
    && normalizeDestination(byId("claim-destination").value) !== normalizeDestination(preparedDestination));
}

function invalidatePreview() {
  preparedRenderValid = false;
  preparedEdited = false;
  previewNeedsRecheck = false;
  preparedDestination = null;
  lastPreparedTxid = null;
  setHidden("claim-step-summary", true);
  setHidden("claim-step-confirm", true);
  setTextIfChanged(byId("claim-preview-status"), "");
}

function satToBtc(sat) {
  return (Number(sat) / 100_000_000).toFixed(8);
}

function renderPrepared(summary, authorized = false) {
  const destination = String(summary.destination || "");
  const txid = String(summary.txid || "");
  if (destination !== preparedDestination || txid !== lastPreparedTxid) preparedRenderValid = false;
  preparedDestination = destination;
  lastPreparedTxid = txid;
  // Only a successful response to this tab's explicit prepare action authorizes Send.
  if (authorized) {
    preparedEdited = false;
    previewNeedsRecheck = false;
    preparedRenderValid = Boolean(destination && /^[0-9a-f]{64}$/.test(txid));
  } else if (!preparedRenderValid) {
    previewNeedsRecheck = true;
  }
  byId("claim-summary-destination").textContent = destination;
  byId("claim-summary-inputs").textContent = `${summary.input_count} · ${satToBtc(summary.total_input_sat)} BTC`;
  byId("claim-summary-fee").textContent = `${formatNumber(summary.fee_sat)} sat · ${formatOne(summary.effective_fee_rate_sat_vb)} sat/vB`;
  byId("claim-summary-payout").textContent = `${satToBtc(summary.output_sat)} BTC`;
  byId("claim-summary-dust").textContent = `${summary.excluded_dust_count} · ${formatNumber(summary.excluded_dust_sat)} sat`;
  if (preparedEdited) {
    setHidden("claim-step-summary", true);
    setHidden("claim-step-confirm", true);
    setTextIfChanged(byId("claim-destination-mismatch"), "Adresse geändert – alte Vorschau verworfen. Bitte erneut prüfen.");
  } else {
    setHidden("claim-step-summary", false);
    setHidden("claim-step-confirm", false);
    setTextIfChanged(byId("claim-preview-status"), previewNeedsRecheck
      ? "Gespeicherte Vorschau – bitte in diesem Tab erneut prüfen, bevor du sendest."
      : "");
  }
}

function renderClaim(claim, hit, claimBusy, statusDetails = null) {
  claimServerBusy = Boolean(claimBusy);
  if (!hit || hit.storage_pending || (claim == null && !claimServerBusy && !claimPending)) {
    byId("claim-panel").classList.add("hidden");
    invalidatePreview();
    syncClaimButtons();
    return;
  }
  byId("claim-panel").classList.remove("hidden");
  if (claim == null) {
    setHidden("claim-step-destination", false);
    setHidden("claim-step-summary", true);
    setHidden("claim-step-confirm", true);
    setHidden("claim-step-result", true);
    invalidatePreview();
    syncClaimButtons();
    return;
  }
  const phase = claimPhase(claim);
  const fields = claimFields(claim);
  if (claimAwaitingOutcome) {
    claimAwaitingPolls += 1;
    if (phase === "Submitted" || phase === "Confirmed" || (!claimBusy && claimAwaitingPolls >= 2)) {
      claimAwaitingOutcome = false;
      claimPending = false;
      claimBusyKind = null;
      preparedRenderValid = false;
      clearClaimActionErrors();
      if (phase !== "Submitted" && phase !== "Confirmed") byId("claim-confirm-error").textContent = CLAIM_UNKNOWN_TEXT;
    }
  }
  if (phase === "Submitted" || phase === "Confirmed") clearClaimActionErrors();
  setHidden("claim-step-destination", !["Idle", "AwaitingOwner", "Prepared", "Failed"].includes(phase));
  setHidden("claim-step-result", !["Submitted", "Confirmed", "Failed"].includes(phase));
  if (phase === "Prepared" && fields.summary && !(claimPending && claimBusyKind === "prepare" && !claimAwaitingOutcome)) {
    renderPrepared(fields.summary);
  } else if (phase !== "Prepared") {
    invalidatePreview();
  }
  const status = byId("claim-result-status");
  const providerUnavailable = Boolean(statusDetails?.unavailable);
  const displayedTxid = fields.txid || (phase === "Failed" ? statusDetails?.pending_txid : "") || "";
  setTextIfChanged(byId("claim-result-txid"), displayedTxid);
  setHidden("claim-result-txid-row", !displayedTxid);
  let resultDetail = "";
  if (phase === "Submitted") {
    setTextIfChanged(status, providerUnavailable
      ? "Eingereicht · Statusabfragen nicht erreichbar"
      : "Eingereicht");
    resultDetail = "Die Einreichung ist noch keine Blockbestätigung. Der Status wird weiter geprüft.";
    if (fields.txid && fields.txid !== lastClaimTxidLogged) {
      lastClaimTxidLogged = fields.txid;
      addLog(`[CLAIM] Eingereicht: ${fields.txid}`, "success");
    }
  } else if (phase === "Confirmed") {
    setTextIfChanged(status, statusDetails?.unavailable
      ? `Zuletzt bekannt: bestätigt in Block ${fields.block_height} · Statusabfragen nicht erreichbar`
      : `Bestätigt in Block ${fields.block_height}`);
  } else if (phase === "Failed") {
    setTextIfChanged(status, providerUnavailable
      ? "Einreichung prüfen · Statusabfragen nicht erreichbar"
      : "Einreichung prüfen");
    resultDetail = CLAIM_FAILED_TEXT[fields.reason] || claimErrorText(fields.reason);
  } else {
    setTextIfChanged(status, "");
  }
  setClassIfChanged(status, `claim-result-status ${phase === "Submitted" ? "claim-status-submitted" : phase === "Confirmed" ? "claim-status-confirmed" : phase === "Failed" ? "claim-status-failed" : ""}${providerUnavailable ? " claim-status-stale" : ""}`);
  if (["Submitted", "Confirmed", "Failed"].includes(phase) && statusDetails && typeof statusDetails === "object") {
    if (providerUnavailable) {
      const lastAttempt = formatUnixTimestamp(statusDetails.last_attempt_unix, "");
      const lastSuccess = formatUnixTimestamp(statusDetails.last_success_unix, "");
      resultDetail = [resultDetail, "Statusabfragen derzeit nicht erreichbar.", lastAttempt && `Letzter Versuch: ${lastAttempt}.`, lastSuccess ? `Zuletzt erfolgreich abgefragt: ${lastSuccess}.` : "Zeitpunkt der letzten erfolgreichen Abfrage nicht verfügbar."].filter(Boolean).join(" ");
    } else if (statusDetails.last_success_unix) {
      resultDetail = [resultDetail, `Letzter Statusabruf: ${formatUnixTimestamp(statusDetails.last_success_unix, "Unbekannt")}.`].filter(Boolean).join(" ");
    }
  }
  setTextIfChanged(byId("claim-result-detail"), resultDetail);
  lastClaimPhase = phase;
  syncClaimButtons();
}

function syncClaimButtons() {
  const blocked = claimPending || claimServerBusy || claimStoragePending;
  byId("btn-claim-prepare").disabled = blocked;
  byId("claim-destination").disabled = blocked;
  byId("btn-claim-confirm").disabled = blocked || !preparedRenderValid || !lastPreparedTxid || destinationEditedAfterPrepare();
  setTextIfChanged(byId("claim-destination-mismatch"), preparedDestination && preparedEdited
    ? "Adresse geändert – alte Vorschau verworfen. Bitte erneut prüfen."
    : "");
  setTextIfChanged(byId("claim-busy-notice"), claimPending || claimServerBusy
    ? "Vorgang läuft – Status wird aktualisiert."
    : "");
}

function hintDestination() {
  const value = byId("claim-destination").value.trim();
  if (value && (value.length < 26 || value.length > 90 || !/^[A-Za-z0-9]+$/.test(value))) {
    byId("claim-destination-error").textContent = "Hinweis: Bitte eine vollständige Bitcoin-Empfangsadresse einfügen.";
  }
}

async function withClaimAction(kind, action, errorTarget) {
  if (claimPending || claimServerBusy || claimStoragePending) return;
  claimPending = true;
  claimBusyKind = kind;
  claimRevision += 1;
  syncClaimButtons();
  try {
    await action();
  } catch (error) {
    preparedRenderValid = false;
    if (error.networkFailure) {
      claimAwaitingOutcome = true;
      claimAwaitingPolls = 0;
      byId(errorTarget).textContent = CLAIM_INFLIGHT_TEXT;
    } else {
      byId(errorTarget).textContent = claimErrorText(error.code || error.message);
    }
  } finally {
    claimRevision += 1;
    if (!claimAwaitingOutcome) {
      claimPending = false;
      claimBusyKind = null;
    }
    syncClaimButtons();
    scheduleStatusPoll(0);
  }
}

function clearClaimActionErrors() {
  setTextIfChanged(byId("claim-destination-error"), "");
  setTextIfChanged(byId("claim-confirm-error"), "");
}

function prepareClaim() {
  if (claimPending || claimServerBusy || claimStoragePending) return;
  clearClaimActionErrors();
  const destination = byId("claim-destination").value.trim();
  invalidatePreview();
  return withClaimAction("prepare", async () => {
    const result = await fetchJson("/api/claim/prepare", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ destination }),
    });
    if (!result.summary) throw new Error("claim_build_failed");
    byId("claim-destination").value = result.summary.destination;
    renderPrepared(result.summary, true);
    lastClaimPhase = "Prepared";
    setHidden("claim-step-result", true);
    addLog("[CLAIM] Adresse und Auszahlung geprüft", "success");
  }, "claim-destination-error");
}

function confirmClaim() {
  if (!preparedRenderValid || !lastPreparedTxid || destinationEditedAfterPrepare() || claimPending || claimServerBusy || claimStoragePending) return;
  clearClaimActionErrors();
  const destination = preparedDestination;
  const prepared_txid = lastPreparedTxid;
  preparedRenderValid = false;
  return withClaimAction("confirm", async () => {
    const result = await fetchJson("/api/claim/confirm", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ destination, prepared_txid }),
    });
    renderClaim({ Submitted: { txid: result.txid } }, { storage_pending: false }, false);
  }, "claim-confirm-error");
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
