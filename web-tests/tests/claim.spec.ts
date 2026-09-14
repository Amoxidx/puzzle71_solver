import { test, expect, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

const SENTINEL_PRIVKEY = "SENTINEL_PRIVKEY_DO_NOT_SHOW";
const SENTINEL_TXHEX = "SENTINEL_TXHEX_DEADBEEFCAFE";
const SENTINEL_CODE = "SENTINEL_CODE_999999";
const SENTINEL_PUBKEY = "SENTINEL_PUBKEY_COMPRESSED";
const SENTINEL_FIELDS = {
  private_key: SENTINEL_PRIVKEY,
  tx_hex: SENTINEL_TXHEX,
  code: SENTINEL_CODE,
  pubkey: SENTINEL_PUBKEY,
};

const DESTINATION = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
const TXID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const HIT = {
  bitcoin_address: "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
  saved_filename: "FOUND_KEY.txt",
  timestamp_unix: 1,
};

const SUMMARY = {
  network: "bitcoin",
  destination: DESTINATION,
  input_count: 3,
  total_input_sat: 710000000,
  output_sat: 709400000,
  fee_sat: 600000,
  vsize: 300,
  effective_fee_rate_sat_vb: 2000,
  txid: TXID,
  excluded_dust_count: 55,
  excluded_dust_sat: 184686,
};

const AWAITING = {
  AwaitingOwner: { alert_sent: true, alerts_remaining: 3, attempts_remaining: 5 },
};

const PREPARED = {
  Prepared: {
    summary: SUMMARY,
    alert_sent: true,
    alerts_remaining: 3,
    attempts_remaining: 5,
  },
};

const SUBMITTED = { Submitted: { txid: TXID, submitted_at_unix: 1 } };
const CONFIRMED = { Confirmed: { txid: TXID, block_height: 900000 } };
const LOCKED = "Locked";
const FAILED = { Failed: { reason: "submission_rejected" } };

function withClaimSentinels(claim: unknown): unknown {
  if (!claim || typeof claim !== "object" || Array.isArray(claim)) return claim;
  const record = claim as Record<string, unknown>;
  const next: Record<string, unknown> = { ...record };
  for (const key of ["AwaitingOwner", "Prepared", "Submitted", "Confirmed", "Failed"]) {
    const inner = record[key];
    if (!inner || typeof inner !== "object" || Array.isArray(inner)) continue;
    const fields = inner as Record<string, unknown>;
    const patched: Record<string, unknown> = { ...fields, ...SENTINEL_FIELDS };
    if (fields.summary && typeof fields.summary === "object" && !Array.isArray(fields.summary)) {
      patched.summary = { ...(fields.summary as Record<string, unknown>), ...SENTINEL_FIELDS };
    }
    next[key] = patched;
  }
  return next;
}

function statusPayload(claim: unknown, hit: unknown, claimBusy?: boolean) {
  const payload: Record<string, unknown> = {
    is_running: false,
    mode: "HIGH",
    total_keys_tested: "16777216",
    total_blocks_tested: 1,
    current_keys_per_sec: 0,
    avg_keys_per_sec: 1000000,
    estimated_package_power_watts: 20,
    estimated_soc_temp_celsius: 55,
    process_cpu_load_pct: 2,
    runtime_secs: 10,
    target_gpu_duty_pct: 85,
    last_gpu_active_ms: 850,
    last_throttle_sleep_ms: 150,
    checkpoint_saved_timestamp: 1,
    hit,
    claim: withClaimSentinels(claim),
    last_error: null,
    ...SENTINEL_FIELDS,
  };
  if (claimBusy !== undefined) {
    payload.claim_busy = claimBusy;
  }
  return payload;
}

function isStatusOk(res: { url: () => string; ok: () => boolean }): boolean {
  return res.url().includes("/api/status") && res.ok();
}

async function gotoDashboard(page: Page): Promise<void> {
  const painted = page.waitForResponse(isStatusOk);
  await page.goto("/");
  await painted;
}

type LiveStatus = { claim: unknown; hit: unknown; claim_busy?: boolean };

async function mockStatus(page: Page, live: LiveStatus): Promise<void> {
  await page.route("**/api/status", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(statusPayload(live.claim, live.hit, live.claim_busy)),
    });
  });
}

async function openClaim(page: Page, claim: unknown, hit: unknown = HIT): Promise<LiveStatus> {
  const live: LiveStatus = { claim, hit };
  await mockStatus(page, live);
  await gotoDashboard(page);
  return live;
}

async function expectNoSentinels(page: Page): Promise<void> {
  const body = page.locator("body");
  await expect(body).not.toContainText(SENTINEL_PRIVKEY);
  await expect(body).not.toContainText(SENTINEL_TXHEX);
  await expect(body).not.toContainText(SENTINEL_CODE);
  await expect(body).not.toContainText(SENTINEL_PUBKEY);
  await expect(page.locator("#log-container")).not.toContainText(SENTINEL_PRIVKEY);
  await expect(page.locator("#log-container")).not.toContainText(SENTINEL_TXHEX);
  await expect(page.locator("#log-container")).not.toContainText(SENTINEL_CODE);
  await expect(page.locator("#log-container")).not.toContainText(SENTINEL_PUBKEY);
}

function grouped(value: string): string {
  const parts = [];
  for (let i = 0; i < value.length; i += 4) parts.push(value.slice(i, i + 4));
  return parts.join(" ");
}

test.describe("Puzzle #71 claim panel", () => {
  test("hidden without a hit", async ({ page }) => {
    await openClaim(page, AWAITING, null);
    await expect(page.locator("#claim-panel")).toHaveClass(/hidden/);
    await expect(page.locator("#claim-panel")).not.toBeVisible();
  });

  test("visible with hit and AwaitingOwner title PUZZLE SOLVED", async ({ page }) => {
    await openClaim(page, AWAITING);
    await expect(page.locator("#claim-panel")).toBeVisible();
    await expect(page.locator("#claim-title")).toHaveText("PUZZLE SOLVED");
    await expectNoSentinels(page);
  });

  test("prepare sends trimmed destination as JSON", async ({ page }) => {
    const live = await openClaim(page, AWAITING);
    let captured: { body?: string; contentType?: string } = {};
    await page.route("**/api/claim/prepare", async (route) => {
      captured.body = route.request().postData() || "";
      captured.contentType = route.request().headers()["content-type"];
      live.claim = PREPARED;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          summary: SUMMARY,
          private_key: SENTINEL_PRIVKEY,
          tx_hex: SENTINEL_TXHEX,
        }),
      });
    });

    await page.locator("#claim-destination").fill(`  ${DESTINATION}  `);
    await page.locator("#btn-claim-prepare").click();

    await expect.poll(() => captured.body).toBe(JSON.stringify({ destination: DESTINATION }));
    expect(captured.contentType).toBe("application/json");
    await expect(page.locator("#claim-summary-destination")).toHaveText(grouped(DESTINATION));
    await expect(page.locator("#claim-summary-inputs")).toContainText("3");
    await expect(page.locator("#claim-summary-inputs")).toContainText("7.10000000");
    await expect(page.locator("#claim-summary-fee")).toContainText("600");
    await expect(page.locator("#claim-summary-fee")).toContainText("2000");
    await expect(page.locator("#claim-summary-payout")).toContainText("7.09400000");
    await expect(page.locator("#claim-summary-dust")).toContainText("55");
    await expect(page.locator("#claim-summary-dust")).toContainText("184");
  });

  test("confirm stays disabled until checkbox and six digits", async ({ page }) => {
    await openClaim(page, PREPARED);
    await page.locator("#claim-destination").fill(DESTINATION);
    const confirm = page.locator("#btn-claim-confirm");
    await expect(page.locator("#claim-step-summary")).toBeVisible();
    await expect(confirm).toBeDisabled();

    await page.locator("#claim-verified-on-device").check();
    await expect(confirm).toBeDisabled();

    await page.locator("#claim-code").fill("12345");
    await expect(confirm).toBeDisabled();

    await page.locator("#claim-code").fill("123456");
    await expect(confirm).toBeEnabled();

    let captured = "";
    await page.route("**/api/claim/confirm", async (route) => {
      captured = route.request().postData() || "";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ txid: TXID }),
      });
    });
    await confirm.click();
    await expect.poll(() => captured).toBe(JSON.stringify({ destination: DESTINATION, code: "123456" }));
  });

  test("wrong_code alert includes remaining attempts", async ({ page }) => {
    await openClaim(page, PREPARED);
    await page.locator("#claim-destination").fill(DESTINATION);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("000000");
    await page.route("**/api/claim/confirm", async (route) => {
      await route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ error: "wrong_code", remaining_attempts: 3 }),
      });
    });
    await page.locator("#btn-claim-confirm").click();
    const alert = page.locator("#claim-confirm-error");
    await expect(alert).toHaveAttribute("role", "alert");
    await expect(alert).toContainText("3");
  });

  test("Submitted, Confirmed, Locked and Failed render their copy", async ({ page }) => {
    const live = await openClaim(page, SUBMITTED);
    await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
    await expect(page.locator("#claim-result-txid")).toHaveText(TXID);
    await expect(page.locator("#claim-result-detail")).toContainText("MARA-Block");
    await expectNoSentinels(page);

    live.claim = CONFIRMED;
    await expect(page.locator("#claim-result-status")).toHaveText("Bestätigt in Block 900000");
    await expectNoSentinels(page);

    live.claim = LOCKED;
    await expect(page.locator("#claim-result-status")).toContainText("Gesperrt nach 5 Fehlversuchen");
    await expectNoSentinels(page);

    live.claim = FAILED;
    await expect(page.locator("#claim-result-status")).toHaveText("Fehlgeschlagen");
    await expect(page.locator("#claim-result-detail")).toContainText("Abgelehnt");
    await expectNoSentinels(page);
  });

  test("polling does not overwrite the destination field", async ({ page }) => {
    await openClaim(page, AWAITING);
    const typed = "bc1qstayputduringpollingxxxxxxxxxxxxxxxx";
    await page.locator("#claim-destination").fill(typed);
    await page.waitForResponse(isStatusOk);
    await page.waitForResponse(isStatusOk);
    await expect(page.locator("#claim-destination")).toHaveValue(typed);
  });

  test("sentinels from mocked payloads never appear on the page", async ({ page }) => {
    const live = await openClaim(page, AWAITING);
    await page.route("**/api/claim/prepare", async (route) => {
      live.claim = PREPARED;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ summary: { ...SUMMARY, ...SENTINEL_FIELDS }, ...SENTINEL_FIELDS }),
      });
    });
    await page.route("**/api/claim/confirm", async (route) => {
      live.claim = SUBMITTED;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ txid: TXID, ...SENTINEL_FIELDS }),
      });
    });

    await page.locator("#claim-destination").fill(DESTINATION);
    await page.locator("#btn-claim-prepare").click();
    await expect(page.locator("#claim-step-summary")).toBeVisible();
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await page.locator("#btn-claim-confirm").click();
    await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
    await expectNoSentinels(page);
  });

  test("no external requests", async ({ page }) => {
    const urls: string[] = [];
    page.on("request", (req) => urls.push(req.url()));
    await openClaim(page, PREPARED);
    const offenders = urls.filter((url) => {
      if (new URL(url).origin === new URL(page.url()).origin) return false;
      if (url.startsWith("data:")) return false;
      if (url.startsWith("about:")) return false;
      return true;
    });
    expect(offenders, `external requests: ${offenders.join(", ")}`).toEqual([]);
  });

  test("no horizontal overflow at 375/768/1024/1440 with the panel visible", async ({ page }) => {
    await openClaim(page, PREPARED);
    await expect(page.locator("#claim-panel")).toBeVisible();
    for (const width of [375, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      const fits = await page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth
      );
      expect(fits, `horizontal overflow at ${width}px`).toBeTruthy();
    }
  });

  test("Prepared prefills an empty destination and confirm sends the prepared address", async ({
    page,
  }) => {
    await openClaim(page, PREPARED);
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    let captured = "";
    await page.route("**/api/claim/confirm", async (route) => {
      captured = route.request().postData() || "";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ txid: TXID }),
      });
    });
    await page.locator("#btn-claim-confirm").click();
    await expect
      .poll(() => captured)
      .toBe(JSON.stringify({ destination: DESTINATION, code: "123456" }));
  });

  test("editing destination after Prepared disables confirm and shows an alert", async ({
    page,
  }) => {
    await openClaim(page, PREPARED);
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
    let confirmCalls = 0;
    await page.route("**/api/claim/confirm", async (route) => {
      confirmCalls += 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ txid: TXID }),
      });
    });
    await page.locator("#claim-destination").fill("bc1qdifferentaddressxxxxxxxxxxxxxxxxxxxxx");
    await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
    const hint = page.locator("#claim-destination-mismatch");
    await expect(hint).toHaveAttribute("role", "alert");
    await expect(hint).toHaveText("Adresse wurde nach dem Prüfen geändert – bitte erneut prüfen");
    expect(confirmCalls).toBe(0);
  });

  test("summary_changed message survives the next status poll", async ({ page }) => {
    const live = await openClaim(page, PREPARED);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await page.route("**/api/claim/confirm", async (route) => {
      live.claim = AWAITING;
      await route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ error: "summary_changed" }),
      });
    });
    await page.locator("#btn-claim-confirm").click();
    const alert = page.locator("#claim-confirm-error");
    await expect(alert).toHaveAttribute("role", "alert");
    await expect(alert).toContainText("Zusammenfassung hat sich geändert");
    await page.waitForResponse(isStatusOk);
    await expect(alert).toBeVisible();
    await expect(alert).toContainText("Zusammenfassung hat sich geändert");
  });

  test("confirm network abort waits for status instead of showing an error", async ({ page }) => {
    const live = await openClaim(page, PREPARED);
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await page.route("**/api/claim/confirm", (route) => route.abort());
    await page.locator("#btn-claim-confirm").click();
    const inflight = page.locator("#claim-confirm-error");
    await expect(inflight).toHaveText("Vorgang läuft noch – Status wird abgefragt");
    await expect(page.locator("#claim-panel")).not.toContainText("Unbekannter Fehler");
    await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
    live.claim = SUBMITTED;
    await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
    await expect(page.locator("#claim-panel")).not.toContainText("Unbekannter Fehler");
    await expect(page.locator("#claim-panel")).not.toContainText("Vorgang läuft noch");
  });

  test("prepare with uppercase bech32 canonicalizes the field and confirm sends lowercase", async ({
    page,
  }) => {
    const live = await openClaim(page, AWAITING);
    await page.route("**/api/claim/prepare", async (route) => {
      live.claim = PREPARED;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ summary: SUMMARY }),
      });
    });
    await page.locator("#claim-destination").fill(DESTINATION.toUpperCase());
    await page.locator("#btn-claim-prepare").click();
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await expect(page.locator("#claim-destination-mismatch")).toHaveText("");
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
    let captured = "";
    await page.route("**/api/claim/confirm", async (route) => {
      captured = route.request().postData() || "";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ txid: TXID }),
      });
    });
    await page.locator("#btn-claim-confirm").click();
    await expect
      .poll(() => captured)
      .toBe(JSON.stringify({ destination: DESTINATION, code: "123456" }));
  });

  test("confirm abort ends waiting when claim_busy becomes false", async ({ page }) => {
    const live = await openClaim(page, PREPARED);
    live.claim_busy = true;
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await page.route("**/api/claim/confirm", (route) => route.abort());
    await page.locator("#btn-claim-confirm").click();
    const alert = page.locator("#claim-confirm-error");
    await expect(alert).toHaveText("Vorgang läuft noch – Status wird abgefragt");
    await expect(alert).toHaveAttribute("role", "alert");
    await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
    await expect(page.locator("#btn-claim-prepare")).toBeDisabled();
    live.claim_busy = false;
    await expect(alert).toHaveText(
      "Ergebnis unbekannt – bitte Status prüfen und den Code neu eingeben"
    );
    await expect(alert).toHaveAttribute("role", "alert");
    await expect(page.locator("#claim-code")).toHaveValue("");
    await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
    await expect(page.locator("#btn-claim-prepare")).toBeEnabled();
    await page.locator("#claim-code").fill("123456");
    await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
  });

  test("prepare abort with unchanged prepared txid does not show unknown", async ({ page }) => {
    const live = await openClaim(page, PREPARED);
    live.claim_busy = true;
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await page.route("**/api/claim/prepare", (route) => route.abort());
    await page.locator("#btn-claim-prepare").click();
    await expect(page.locator("#claim-destination-error")).toHaveText(
      "Vorgang läuft noch – Status wird abgefragt"
    );
    await expect(page.locator("#btn-claim-prepare")).toBeDisabled();
    live.claim_busy = false;
    await expect(page.locator("#btn-claim-prepare")).toBeEnabled();
    await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
    await expect(page.locator("#claim-destination-error")).toHaveText(
      "Erneute Prüfung ohne Rückmeldung – die angezeigte Zusammenfassung gilt weiter"
    );
    await expect(page.locator("#claim-confirm-error")).toHaveText("");
    await expect(page.locator("#claim-panel")).not.toContainText("Ergebnis unbekannt");
  });

  test("Prepared shows remaining attempts and updates them on later polls", async ({
    page,
  }) => {
    const live = await openClaim(page, PREPARED);
    await expect(page.locator("#claim-attempts")).toHaveText(
      "Verbleibende Code-Versuche: 5"
    );
    live.claim = {
      Prepared: {
        summary: SUMMARY,
        alert_sent: true,
        alerts_remaining: 3,
        attempts_remaining: 4,
      },
    };
    await expect(page.locator("#claim-attempts")).toHaveText(
      "Verbleibende Code-Versuche: 4"
    );
  });

  test("confirm abort that lands in AwaitingOwner shows summary_changed", async ({
    page,
  }) => {
    const live = await openClaim(page, PREPARED);
    live.claim_busy = true;
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await page.route("**/api/claim/confirm", (route) => route.abort());
    await page.locator("#btn-claim-confirm").click();
    await expect(page.locator("#claim-confirm-error")).toHaveText(
      "Vorgang läuft noch – Status wird abgefragt"
    );
    live.claim = AWAITING;
    live.claim_busy = false;
    const alert = page.locator("#claim-destination-error");
    await expect(alert).toHaveText(
      "Zusammenfassung hat sich geändert – Adresse erneut prüfen"
    );
    await expect(page.locator("#claim-panel")).not.toContainText("Ergebnis unbekannt");
    await page.waitForResponse(isStatusOk);
    await expect(alert).toHaveText(
      "Zusammenfassung hat sich geändert – Adresse erneut prüfen"
    );
    await expect(alert).toBeVisible();
    await expect(page.locator("#claim-panel")).not.toContainText("Ergebnis unbekannt");
  });

  test("prepare abort with a new prepared txid shows the new summary", async ({ page }) => {
    const live = await openClaim(page, PREPARED);
    live.claim_busy = true;
    await page.route("**/api/claim/prepare", (route) => route.abort());
    await page.locator("#btn-claim-prepare").click();
    await expect(page.locator("#claim-destination-error")).toHaveText(
      "Vorgang läuft noch – Status wird abgefragt"
    );
    await expect(page.locator("#btn-claim-prepare")).toBeDisabled();
    const newTxid = "b".repeat(64);
    live.claim = {
      Prepared: {
        summary: { ...SUMMARY, txid: newTxid, output_sat: 709300000 },
        alert_sent: true,
        alerts_remaining: 3,
        attempts_remaining: 5,
      },
    };
    await expect(page.locator("#claim-summary-payout")).toContainText("7.09300000");
    await expect(page.locator("#btn-claim-prepare")).toBeEnabled();
    await expect(page.locator("#claim-panel")).not.toContainText("Ergebnis unbekannt");
    await expect(page.locator("#claim-destination-error")).not.toHaveText(
      "Vorgang läuft noch – Status wird abgefragt"
    );
  });

  test("re-pasting uppercase bech32 after Prepared does not trip the mismatch lock", async ({
    page,
  }) => {
    await openClaim(page, PREPARED);
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await page.locator("#claim-destination").fill(DESTINATION.toUpperCase());
    await expect(page.locator("#claim-destination-mismatch")).toHaveText("");
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
    let captured = "";
    await page.route("**/api/claim/confirm", async (route) => {
      captured = route.request().postData() || "";
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ txid: TXID }),
      });
    });
    await page.locator("#btn-claim-confirm").click();
    await expect
      .poll(() => captured)
      .toBe(JSON.stringify({ destination: DESTINATION, code: "123456" }));

    const other = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
    await page.locator("#claim-destination").fill(other);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    await expect(page.locator("#claim-destination-mismatch")).toHaveText(
      "Adresse wurde nach dem Prüfen geändert – bitte erneut prüfen"
    );
    await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
  });

  test("Submitted clears a previous wrong_code alert", async ({ page }) => {
    const live = await openClaim(page, PREPARED);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("000000");
    await page.route("**/api/claim/confirm", async (route) => {
      await route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ error: "wrong_code", remaining_attempts: 3 }),
      });
    });
    await page.locator("#btn-claim-confirm").click();
    const alert = page.locator("#claim-confirm-error");
    await expect(alert).toContainText("Falscher Code");
    live.claim = SUBMITTED;
    await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
    await expect(alert).toHaveText("");
    await expect(page.locator("#claim-destination-error")).toHaveText("");
    await expect(page.locator("#claim-panel")).not.toContainText("Falscher Code");
  });

  test("screenshots for AwaitingOwner, Prepared and Submitted", async ({ page }) => {
    test.setTimeout(120_000);
    const dir = path.join("screenshots");
    fs.mkdirSync(dir, { recursive: true });
    const widths = [1440, 900, 768, 720, 375];
    const live = await openClaim(page, AWAITING);

    for (const width of widths) {
      await page.setViewportSize({ width, height: 1100 });
      await expect(page.locator("#claim-title")).toHaveText("PUZZLE SOLVED");
      await page.screenshot({
        path: path.join(dir, `claim-AwaitingOwner-${width}.png`),
        fullPage: true,
      });
    }

    live.claim = PREPARED;
    await expect(page.locator("#claim-step-summary")).toBeVisible();
    await expect(page.locator("#claim-destination")).toHaveValue(DESTINATION);
    await page.locator("#claim-verified-on-device").check();
    await page.locator("#claim-code").fill("123456");
    for (const width of widths) {
      await page.setViewportSize({ width, height: 1400 });
      await page.screenshot({
        path: path.join(dir, `claim-Prepared-${width}.png`),
        fullPage: true,
      });
    }

    live.claim = SUBMITTED;
    await expect(page.locator("#claim-result-txid")).toHaveText(TXID);
    for (const width of widths) {
      await page.setViewportSize({ width, height: 1100 });
      await page.screenshot({
        path: path.join(dir, `claim-Submitted-${width}.png`),
        fullPage: true,
      });
    }
  });
});
