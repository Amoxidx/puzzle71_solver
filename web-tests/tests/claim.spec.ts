import { test, expect, type Page } from "@playwright/test";

const DESTINATION = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
const OTHER_DESTINATION = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
const TXID = "a".repeat(64);
const TXID_B = "b".repeat(64);
const HIT = { bitcoin_address: "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU", saved_filename: "FOUND_KEY.txt", timestamp_unix: 1, storage_pending: false };
const SUMMARY = { network: "bitcoin", destination: DESTINATION, input_count: 3, total_input_sat: 710000000, output_sat: 709400000, fee_sat: 600000, vsize: 300, effective_fee_rate_sat_vb: 2000, txid: TXID, excluded_dust_count: 55, excluded_dust_sat: 184686 };
type Summary = typeof SUMMARY;
type LiveStatus = { claim: unknown; hit: unknown; claim_busy: boolean; last_error: string | null };

function statusPayload(live: LiveStatus) {
  return {
    is_running: false, mode: "HIGH", total_keys_tested: "16777216", total_blocks_tested: 1,
    current_keys_per_sec: 0, avg_keys_per_sec: 1000000, estimated_package_power_watts: 20,
    estimated_soc_temp_celsius: 55, process_cpu_load_pct: 2, runtime_secs: 10,
    target_gpu_duty_pct: 85, last_gpu_active_ms: 850, last_throttle_sleep_ms: 150,
    checkpoint_saved_timestamp: 1, ...live,
  };
}

async function openClaim(page: Page, claim: unknown = "AwaitingOwner", hit: unknown = HIT) {
  const live: LiveStatus = { claim, hit, claim_busy: false, last_error: null };
  await page.route("**/api/status", (route) => route.fulfill({ json: statusPayload(live) }));
  await page.goto("/");
  if (hit && claim) await expect(page.locator("#claim-panel")).toBeVisible();
  return live;
}

async function prepare(page: Page, live: LiveStatus, summary: Summary = SUMMARY) {
  await page.route("**/api/claim/prepare", async (route) => {
    expect(route.request().postDataJSON()).toEqual({ destination: summary.destination });
    live.claim = { Prepared: { summary } };
    await route.fulfill({ json: { summary } });
  });
  await page.locator("#claim-destination").fill(summary.destination);
  await page.locator("#btn-claim-prepare").click();
  await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
}

test("wallet address and preview suffice; no code or device checkbox is required", async ({ page }) => {
  const live = await openClaim(page);
  await expect(page.locator("#claim-code, #claim-verified-on-device, #btn-claim-resend")).toHaveCount(0);
  await prepare(page, live);
  await expect(page.locator("#claim-summary-destination")).toHaveText(DESTINATION);
  await expect(page.locator("#claim-summary-payout")).toContainText("7.09400000 BTC");
  await expect(page.locator("#claim-summary-fee")).toContainText("600");
  let confirms = 0;
  await page.route("**/api/claim/confirm", async (route) => {
    confirms += 1;
    expect(route.request().postDataJSON()).toEqual({ destination: DESTINATION, prepared_txid: TXID });
    live.claim = { Submitted: { txid: TXID, submitted_at_unix: 1 } };
    await route.fulfill({ json: { txid: TXID } });
  });
  expect(confirms).toBe(0);
  await page.locator("#btn-claim-confirm").click();
  await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
  expect(confirms).toBe(1);
});

test("editing the destination invalidates Send even after typing the old address again", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  await page.locator("#claim-destination").fill(OTHER_DESTINATION);
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
  await expect(page.locator("#claim-destination-mismatch")).toContainText("erneut prüfen");
  await page.locator("#claim-destination").fill(DESTINATION);
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
});

test("a second prepare hides A until B is rendered and sends exactly B's txid", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  const summaryB = { ...SUMMARY, txid: TXID_B, fee_sat: 800000, output_sat: 709200000 };
  let release: (() => void) | undefined;
  const delayed = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/claim/prepare", async (route) => {
    await delayed;
    live.claim = { Prepared: { summary: summaryB } };
    await route.fulfill({ json: { summary: summaryB } });
  });
  await page.locator("#btn-claim-prepare").click();
  await expect(page.locator("#claim-step-summary")).toBeHidden();
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
  release!();
  await expect(page.locator("#claim-summary-payout")).toContainText("7.09200000 BTC");
  await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
  let payload: unknown;
  await page.route("**/api/claim/confirm", async (route) => {
    payload = route.request().postDataJSON();
    live.claim = { Submitted: { txid: TXID_B, submitted_at_unix: 1 } };
    await route.fulfill({ json: { txid: TXID_B } });
  });
  await page.locator("#btn-claim-confirm").click();
  await expect(page.locator("#claim-result-txid")).toHaveText(TXID_B);
  expect(payload).toEqual({ destination: DESTINATION, prepared_txid: TXID_B });
});

test("a failed reprepare cannot send the previous preview", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  await page.route("**/api/claim/prepare", async (route) => {
    live.claim = "AwaitingOwner";
    await route.fulfill({ status: 503, json: { error: "network_error" } });
  });
  await page.locator("#btn-claim-prepare").click();
  await expect(page.locator("#claim-destination-error")).toContainText("Netzwerkfehler");
  await expect(page.locator("#claim-step-summary")).toBeHidden();
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
});

test("a Prepared status after reload requires this tab to prepare before Send", async ({ page }) => {
  await openClaim(page, { Prepared: { summary: SUMMARY } });
  await expect(page.locator("#claim-summary-destination")).toHaveText(DESTINATION);
  await page.locator("#claim-destination").fill(DESTINATION);
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
});

test("a changed preview from another tab invalidates this tab's Send authorization", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  live.claim = { Prepared: { summary: { ...SUMMARY, txid: TXID_B, output_sat: 709200000 } } };
  await expect(page.locator("#claim-summary-payout")).toContainText("7.09200000 BTC");
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
});

test("double clicking Send issues one request while submission is pending", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  let calls = 0;
  let release: (() => void) | undefined;
  const delayed = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/claim/confirm", async (route) => {
    calls += 1;
    await delayed;
    live.claim = { Submitted: { txid: TXID, submitted_at_unix: 1 } };
    await route.fulfill({ json: { txid: TXID } });
  });
  await page.locator("#btn-claim-confirm").evaluate((button: HTMLButtonElement) => { button.click(); button.click(); });
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
  await expect.poll(() => calls).toBe(1);
  release!();
  await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
  expect(calls).toBe(1);
});

test("lost confirm response recovers Submitted through polling without another request", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  let calls = 0;
  await page.route("**/api/claim/confirm", async (route) => {
    calls += 1;
    live.claim = { Submitted: { txid: TXID, submitted_at_unix: 1 } };
    await route.abort();
  });
  await page.locator("#btn-claim-confirm").click();
  await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
  await expect(page.locator("#claim-result-txid")).toHaveText(TXID);
  expect(calls).toBe(1);
});

for (const phase of ["Submitted", "Confirmed"]) {
  test(`HTTP submission_unknown warning clears after polled ${phase} without another send`, async ({ page }) => {
    const live = await openClaim(page);
    await prepare(page, live);
    let calls = 0;
    await page.route("**/api/claim/confirm", async (route) => {
      calls += 1;
      await route.fulfill({ status: 400, json: { error: "submission_unknown" } });
    });
    await page.locator("#btn-claim-confirm").click();
    await expect(page.locator("#claim-confirm-error")).toContainText("Einreichung unklar");
    await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
    live.claim = phase === "Submitted"
      ? { Submitted: { txid: TXID, submitted_at_unix: 1 } }
      : { Confirmed: { txid: TXID, block_height: 900000 } };
    await expect(page.locator("#claim-result-status")).toHaveText(
      phase === "Submitted" ? "Eingereicht" : "Bestätigt in Block 900000",
    );
    await expect(page.locator("#claim-result-txid")).toHaveText(TXID);
    await expect(page.locator("#claim-confirm-error")).toBeEmpty();
    expect(calls).toBe(1);
  });
}

test("lost prepare response shows a polled preview but requires a new prepare", async ({ page }) => {
  const live = await openClaim(page);
  await page.route("**/api/claim/prepare", async (route) => {
    live.claim = { Prepared: { summary: SUMMARY } };
    await route.abort();
  });
  await page.locator("#claim-destination").fill(DESTINATION);
  await page.locator("#btn-claim-prepare").click();
  await expect(page.locator("#claim-summary-destination")).toHaveText(DESTINATION);
  await expect(page.locator("#btn-claim-prepare")).toBeEnabled();
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
});

test("lost confirm response with unchanged Prepared requires a fresh prepare", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  await page.route("**/api/claim/confirm", (route) => route.abort());
  await page.locator("#btn-claim-confirm").click();
  await expect(page.locator("#claim-confirm-error")).toContainText("Ergebnis unklar");
  await expect(page.locator("#btn-claim-prepare")).toBeEnabled();
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
});

for (const error of ["prepared_txid_mismatch", "summary_changed", "destination_mismatch", "storage_error"]) {
  test(`confirm ${error} keeps Send disabled until a fresh prepare`, async ({ page }) => {
    const live = await openClaim(page);
    await prepare(page, live);
    await page.route("**/api/claim/confirm", (route) => route.fulfill({ status: 400, json: { error } }));
    await page.locator("#btn-claim-confirm").click();
    await expect(page.locator("#claim-confirm-error")).not.toBeEmpty();
    await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
    await expect(page.locator("#btn-claim-prepare")).toBeEnabled();
  });
}

test("pending hit storage takes priority over last_error and blocks payout until durable", async ({ page }) => {
  const live: LiveStatus = { claim: { Prepared: { summary: SUMMARY } }, hit: { ...HIT, saved_filename: "", storage_pending: true }, claim_busy: false, last_error: "disk sync failed" };
  await page.route("**/api/status", (route) => route.fulfill({ json: statusPayload(live) }));
  await page.goto("/");
  await expect(page.locator("#status-text")).toHaveText("Treffer bestätigt – Speicherung wird wiederholt");
  await expect(page.locator("#hit-filename")).toHaveText("Speicherung ausstehend");
  await expect(page.locator("#claim-panel")).toBeHidden();
  await expect(page.locator("#btn-claim-confirm")).toBeDisabled();
  live.hit = HIT;
  live.last_error = null;
  live.claim = "AwaitingOwner";
  await expect(page.locator("#claim-panel")).toBeVisible();
  await expect(page.locator("#btn-claim-prepare")).toBeEnabled();
  await expect(page.locator("#hit-filename")).toHaveText("FOUND_KEY.txt");
});

test("reorg transitions Confirmed back to Submitted and then Confirmed", async ({ page }) => {
  const live = await openClaim(page, { Confirmed: { txid: TXID, block_height: 900000 } });
  await expect(page.locator("#claim-result-status")).toHaveText("Bestätigt in Block 900000");
  live.claim = { Submitted: { txid: TXID, submitted_at_unix: 1 } };
  await expect(page.locator("#claim-result-status")).toHaveText("Eingereicht");
  live.claim = { Confirmed: { txid: TXID, block_height: 900001 } };
  await expect(page.locator("#claim-result-status")).toHaveText("Bestätigt in Block 900001");
});

test("mocked secret fields are not rendered into the DOM or log", async ({ page }) => {
  const sentinel = "SENTINEL_PRIVATE_MATERIAL";
  await openClaim(page, { Prepared: { summary: { ...SUMMARY, private_key: sentinel, tx_hex: sentinel }, code: sentinel, pubkey: sentinel } });
  await expect(page.locator("#claim-step-summary")).toBeVisible();
  await expect(page.locator("body")).not.toContainText(sentinel);
  await expect(page.locator("#log-container")).not.toContainText(sentinel);
});

test("claim panel stays hidden without a hit", async ({ page }) => {
  await openClaim(page, "AwaitingOwner", null);
  await expect(page.locator("#claim-panel")).toBeHidden();
});

test("a status response started before prepare B cannot replace its rendered preview", async ({ page }) => {
  const live = await openClaim(page);
  await prepare(page, live);
  let startOld: (() => void) | undefined;
  let releaseOld: (() => void) | undefined;
  const started = new Promise<void>((resolve) => { startOld = resolve; });
  const delayed = new Promise<void>((resolve) => { releaseOld = resolve; });
  let captured = false;
  await page.route("**/api/status", async (route) => {
    if (!captured) {
      captured = true;
      const oldPayload = statusPayload({ ...live });
      startOld!();
      await delayed;
      await route.fulfill({ json: oldPayload });
    } else {
      await route.fulfill({ json: statusPayload(live) });
    }
  });
  await started;
  const summaryB = { ...SUMMARY, txid: TXID_B, output_sat: 709200000, fee_sat: 800000 };
  await page.route("**/api/claim/prepare", async (route) => {
    live.claim = { Prepared: { summary: summaryB } };
    await route.fulfill({ json: { summary: summaryB } });
  });
  await page.locator("#btn-claim-prepare").click();
  await expect(page.locator("#claim-summary-payout")).toContainText("7.09200000 BTC");
  await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
  releaseOld!();
  // Observe completion of the stale request and a subsequent fresh poll.
  await expect.poll(async () => page.locator("#claim-summary-payout").textContent()).toContain("7.09200000 BTC");
  await page.waitForResponse((response) => response.url().endsWith("/api/status") && response.ok());
  await expect(page.locator("#claim-summary-payout")).toContainText("7.09200000 BTC");
  await expect(page.locator("#btn-claim-confirm")).toBeEnabled();
});
