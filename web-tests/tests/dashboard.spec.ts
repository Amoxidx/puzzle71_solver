import { test, expect, type Page, type APIRequestContext } from "@playwright/test";

test.describe.configure({ mode: "serial" });

const MODE_BUTTONS = [
  { id: "mode-eco", api: "ECO" },
  { id: "mode-balanced", api: "BALANCED" },
  { id: "mode-high", api: "HIGH" },
  { id: "mode-auto", api: "AUTO" },
  { id: "mode-full", api: "FULL" },
] as const;

const TELEMETRY: { id: string; re: RegExp }[] = [
  { id: "val-speed-mkeys", re: /^\d+[.,]\d{2}$/ },
  { id: "val-speed-current", re: /\d.*keys\/s/ },
  { id: "val-speed-avg", re: /\d.*keys\/s/ },
  { id: "val-power-watts", re: /^\d+[.,]\d$/ },
  { id: "val-keys-per-joule", re: /\d.*Mkeys\/Joule/ },
  { id: "val-keys-per-kwh", re: /\d.*Bkeys\/kWh/ },
  { id: "val-soc-temp", re: /^\d+[.,]\d$/ },
  { id: "val-cpu-load", re: /^\d+[.,]\d%$/ },
  { id: "val-gpu-duty", re: /^\d+[.,]\d% \(Limit \d+([.,]\d)?%\)$/ },
  { id: "val-runtime", re: /^\d+:\d{2}:\d{2}$/ },
  { id: "val-total-keys", re: /\d/ },
  { id: "val-total-blocks", re: /\d/ },
  { id: "val-coverage-pct", re: /^\d+[.,]\d+%$/ },
  { id: "val-cost-start", re: /^\d+[.,]\d+\s*€$/ },
  { id: "val-cost-day", re: /^\d+[.,]\d+\s*€$/ },
  { id: "val-cost-month", re: /^\d+[.,]\d+\s*€$/ },
  { id: "val-cost-year", re: /^\d+[.,]\d+\s*€$/ },
  { id: "val-odds-1h-pct", re: /^[+-]?\d+(\.\d+)?e[+-]?\d+%$/i },
  { id: "val-odds-1h-ratio", re: /^1 zu / },
  { id: "val-odds-24h-pct", re: /^[+-]?\d+(\.\d+)?e[+-]?\d+%$/i },
  { id: "val-odds-24h-ratio", re: /^1 zu / },
  { id: "val-odds-30d-pct", re: /^[+-]?\d+(\.\d+)?e[+-]?\d+%$/i },
  { id: "val-odds-30d-ratio", re: /^1 zu / },
  { id: "val-odds-1y-pct", re: /^[+-]?\d+(\.\d+)?e[+-]?\d+%$/i },
  { id: "val-odds-1y-ratio", re: /^1 zu / },
];

async function statusJson(request: APIRequestContext): Promise<{
  mode: string;
  is_running: boolean;
  target_gpu_duty_pct: number;
}> {
  const res = await request.get("/api/status");
  expect(res.ok()).toBeTruthy();
  return res.json();
}

function parseEuro(text: string): number {
  return parseFloat(text.replace(/\s/g, "").replace("€", "").replace(",", "."));
}

function parseCount(text: string | null): number {
  const m = (text || "").match(/(\d+)/);
  return m ? Number(m[1]) : NaN;
}

function isStatusOk(res: { url: () => string; ok: () => boolean }): boolean {
  return res.url().includes("/api/status") && res.ok();
}

async function gotoDashboard(page: Page): Promise<void> {
  const painted = page.waitForResponse(isStatusOk);
  await page.goto("/");
  await painted;
}

test.describe("Puzzle #71 dashboard", () => {
  test("page loads with puzzle title", async ({ page }) => {
    await gotoDashboard(page);
    await expect(page).toHaveTitle(/Bitcoin Puzzle #71/);
  });

  test("network isolation: no external requests", async ({ page }) => {
    const urls: string[] = [];
    page.on("request", (req) => urls.push(req.url()));
    await gotoDashboard(page);

    const offenders = urls.filter((url) => {
      if (new URL(url).origin === new URL(page.url()).origin) return false;
      if (url.startsWith("data:")) return false;
      if (url.startsWith("about:")) return false;
      return true;
    });
    expect(offenders, `external requests: ${offenders.join(", ")}`).toEqual([]);
  });

  test("telemetry fields are non-empty and formatted", async ({ page }) => {
    await gotoDashboard(page);

    for (const field of TELEMETRY) {
      const loc = page.locator(`#${field.id}`);
      await expect(loc, `#${field.id} missing`).toHaveCount(1);
      await expect(loc, `#${field.id}`).toHaveText(field.re);
    }
  });

  test("hit-alert is hidden in the normal state", async ({ page }) => {
    await page.goto("/");
    const alert = page.locator("#hit-alert");
    await expect(alert).toHaveClass(/hidden/);
    await expect(alert).not.toBeVisible();
    await expect(page.locator("#hit-privkey")).toHaveCount(0);
    await expect(page.locator("#hit-filename")).toHaveCount(1);
    await expect(page.locator("#hit-address")).toHaveCount(1);
  });

  test("no horizontal overflow at 375/768/1024/1440 and mode buttons reachable", async ({ page }) => {
    const widths = [375, 768, 1024, 1440];
    for (const width of widths) {
      await page.setViewportSize({ width, height: 900 });
      await gotoDashboard(page);

      const fits = await page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth
      );
      expect(fits, `horizontal overflow at ${width}px`).toBeTruthy();

      for (const mode of MODE_BUTTONS) {
        const btn = page.locator(`#${mode.id}`);
        await btn.scrollIntoViewIfNeeded();
        await expect(btn, `#${mode.id} not visible at ${width}px`).toBeVisible();
      }
    }
  });

  test("keyboard focus reaches run and mode buttons with a visible ring", async ({ page }) => {
    await gotoDashboard(page);

    const required = [
      "btn-toggle-run",
      "mode-eco",
      "mode-balanced",
      "mode-high",
      "mode-auto",
      "mode-full",
    ];
    const focusedStyles = new Map<string, { outlineWidth: string; outlineStyle: string; boxShadow: string }>();

    for (let i = 0; i < 16 && focusedStyles.size < required.length; i++) {
      await page.keyboard.press("Tab");
      const info = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el || !el.id) return null;
        const cs = getComputedStyle(el);
        return {
          id: el.id,
          outlineWidth: cs.outlineWidth,
          outlineStyle: cs.outlineStyle,
          boxShadow: cs.boxShadow,
        };
      });
      if (info && required.includes(info.id) && !focusedStyles.has(info.id)) {
        focusedStyles.set(info.id, {
          outlineWidth: info.outlineWidth,
          outlineStyle: info.outlineStyle,
          boxShadow: info.boxShadow,
        });
      }
    }

    const missing = required.filter((id) => !focusedStyles.has(id));
    expect(missing, `not reached by Tab: ${missing.join(", ")}`).toEqual([]);

    await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (el && typeof el.blur === "function") el.blur();
    });

    for (const id of required) {
      const focused = focusedStyles.get(id)!;
      const rest = await page.locator(`#${id}`).evaluate((el) => {
        const cs = getComputedStyle(el);
        return {
          outlineWidth: cs.outlineWidth,
          outlineStyle: cs.outlineStyle,
          boxShadow: cs.boxShadow,
        };
      });
      const outlineChanged =
        focused.outlineWidth !== rest.outlineWidth || focused.outlineStyle !== rest.outlineStyle;
      const shadowChanged = focused.boxShadow !== rest.boxShadow;
      const hasVisibleFocus =
        (focused.outlineStyle !== "none" && focused.outlineWidth !== "0px") ||
        (focused.boxShadow !== "none" && focused.boxShadow !== "");
      expect(hasVisibleFocus, `#${id} focused outline=${focused.outlineStyle} ${focused.outlineWidth}`).toBeTruthy();
      expect(outlineChanged || shadowChanged, `#${id} focus style equals rest state`).toBeTruthy();
    }
  });

  test("mode buttons set exclusive active class and backend mode", async ({ page, request }) => {
    await gotoDashboard(page);
    const originalMode = (await statusJson(request)).mode;

    try {
      for (const mode of MODE_BUTTONS) {
        await page.locator(`#${mode.id}`).click();
        await expect(page.locator(`#${mode.id}`)).toHaveClass(/active/);
        await expect(page.locator(`#${mode.id}`)).toHaveAttribute("aria-pressed", "true");
        await expect(page.locator("#status-mode")).toContainText(mode.api === "FULL" ? "MAX" : mode.api);
        for (const other of MODE_BUTTONS) {
          if (other.id === mode.id) continue;
          await expect(page.locator(`#${other.id}`)).not.toHaveClass(/active/);
          await expect(page.locator(`#${other.id}`)).toHaveAttribute("aria-pressed", "false");
        }
        await expect.poll(async () => statusJson(request)).toMatchObject({ mode: mode.api });
        expect((await statusJson(request)).target_gpu_duty_pct).toBeLessThanOrEqual(90);
      }
    } finally {
      const originalButton = MODE_BUTTONS.find((mode) => mode.api === originalMode)!;
      await page.locator(`#${originalButton.id}`).click();
      await expect.poll(async () => (await statusJson(request)).mode).toBe(originalMode);
      await expect(page.locator(`#${originalButton.id}`)).toHaveClass(/active/);
    }
  });

  test("verified hit never exposes a private key in page or status payload", async ({ page }) => {
    const privateKeySentinel = "0x400000000000000123";
    await page.route("**/api/status", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
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
          hit: {
            bitcoin_address: "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
            saved_filename: "FOUND_KEY.txt",
            timestamp_unix: 1,
          },
          last_error: null,
        }),
      });
    });
    await gotoDashboard(page);
    await expect(page.locator("#hit-alert")).toBeVisible();
    await expect(page.locator("#hit-filename")).toHaveText("FOUND_KEY.txt");
    await expect(page.locator("body")).not.toContainText(privateKeySentinel);
    await expect(page.locator("body")).toContainText("niemals über die Web-API");
  });

  test("electricity rate changes daily cost proportionally", async ({ page }) => {
    await gotoDashboard(page);

    const watts = parseFloat((await page.locator("#val-power-watts").innerText()).replace(",", "."));
    const oldDay = parseEuro(await page.locator("#val-cost-day").innerText());
    const expectedNew = (watts * 24) / 1000 * 0.5;
    const expectedOld = (watts * 24) / 1000 * 0.34;

    const input = page.locator("#input-eur-kwh");
    await input.fill("0.50");
    await input.evaluate((el) => el.dispatchEvent(new Event("change", { bubbles: true })));

    await expect
      .poll(async () => parseEuro(await page.locator("#val-cost-day").innerText()))
      .toBeCloseTo(expectedNew, 2);

    const newDay = parseEuro(await page.locator("#val-cost-day").innerText());
    const displayChanges = Math.round(expectedNew * 100) !== Math.round(expectedOld * 100);
    if (displayChanges) {
      expect(newDay).not.toBe(oldDay);
    }

    await input.fill("0.34");
    await input.evaluate((el) => el.dispatchEvent(new Event("change", { bubbles: true })));
    await expect
      .poll(async () => parseEuro(await page.locator("#val-cost-day").innerText()))
      .toBeCloseTo(expectedOld, 2);
  });

  test("selftest appends a result line and increments log-count", async ({ page }) => {
    test.setTimeout(60_000);
    await gotoDashboard(page);

    const before = parseCount(await page.locator("#log-count").textContent());
    expect(before).not.toBeNaN();

    await page.locator("#btn-selftest").click();
    await expect(page.locator("#log-container")).toContainText(/TEST ERFOLG|TEST FEHLER/, {
      timeout: 45_000,
    });

    const after = parseCount(await page.locator("#log-count").textContent());
    expect(after).toBeGreaterThan(before);
  });

  test("start/pause toggle flips status and restores the original run state", async ({ page, request }) => {
    await gotoDashboard(page);

    const originalRunning = (await statusJson(request)).is_running;
    const statusText = page.locator("#status-text");
    const statusPill = page.locator("#status-pill");
    const runLabel = page.locator("#btn-run-label");
    const toggle = page.locator("#btn-toggle-run");

    const originalStatus = (await statusText.innerText()).trim();
    expect(["AKTIV AM SUCHEN", "PAUSIERT"]).toContain(originalStatus);

    try {
      const post = page.waitForResponse(
        (res) =>
          (res.url().includes("/api/start") || res.url().includes("/api/stop")) && res.request().method() === "POST"
      );
      await toggle.click();
      await post;

      if (originalRunning) {
        await expect(statusText).toHaveText("PAUSIERT");
        await expect(statusPill).toHaveClass(/status-paused/);
        await expect(statusPill).not.toHaveClass(/status-running/);
        await expect(runLabel).toHaveText("Suche starten");
        await expect.poll(async () => (await statusJson(request)).is_running).toBe(false);
      } else {
        await expect(statusText).toHaveText("AKTIV AM SUCHEN");
        await expect(statusPill).toHaveClass(/status-running/);
        await expect(statusPill).not.toHaveClass(/status-paused/);
        await expect(runLabel).toHaveText("Suche pausieren");
        await expect.poll(async () => (await statusJson(request)).is_running).toBe(true);
      }
    } finally {
      const nowRunning = (await statusJson(request)).is_running;
      if (nowRunning !== originalRunning) {
        const restore = page.waitForResponse(
          (res) =>
            (res.url().includes("/api/start") || res.url().includes("/api/stop")) &&
            res.request().method() === "POST"
        );
        await toggle.click();
        await restore;
      }
      await expect.poll(async () => (await statusJson(request)).is_running).toBe(originalRunning);
      await expect(statusText).toHaveText(originalRunning ? "AKTIV AM SUCHEN" : "PAUSIERT");
      await expect(runLabel).toHaveText(originalRunning ? "Suche pausieren" : "Suche starten");
    }
  });
});
