import { test, expect } from '@playwright/test';

test.describe('Mobile viewport (375px)', () => {
  test.use({ viewport: { width: 375, height: 667 } });
  
  test('no horizontal scroll on main page', async ({ page }) => {
    await page.goto('/');
    
    // Check body doesn't overflow
    const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
    expect(bodyWidth).toBeLessThanOrEqual(375);
  });
  
  test('labels do not wrap badly on session form', async ({ page }) => {
    await page.goto('/');

    // Wait for the form to be interactive before touching it (matches the
    // defensive wait used in forgery.spec.ts).
    await expect(page.getByRole('button', { name: /run session/i })).toBeVisible();

    // Check form labels are visible and not overlapping
    const labels = page.locator('label');
    const count = await labels.count();
    expect(count).toBeGreaterThan(0);

    // Run a quick session to check verdict panel (pinned seed + explicit
    // backend for determinism, matching the known-good recipe in
    // ledger.spec.ts).
    await page.getByLabel(/scenario/i).selectOption('legitimate');
    await page.getByLabel(/rounds/i).fill('100');
    await page.getByLabel(/backend/i).selectOption('analytic');
    await page.getByLabel(/seed/i).fill('7');
    await page.getByRole('button', { name: /run session/i }).click();

    await expect(page.locator('span.badge', { hasText: /ACCEPT/i })).toBeVisible({ timeout: 60000 });
    
    // Check verdict panel renders without horizontal overflow
    const verdictWidth = await page.evaluate(() => document.body.scrollWidth);
    expect(verdictWidth).toBeLessThanOrEqual(375);
  });
});