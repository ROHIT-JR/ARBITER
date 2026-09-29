import { test, expect } from '@playwright/test';

test.describe('Resubmit replay', () => {
  // Two 800-round analytic sessions plus calibration Monte Carlo exceed the
  // 30s default on shared CI runners.
  test.slow();
  test('resubmit preserves session and evidence chart', async ({ page }) => {
    await page.goto('/');
    
    // Run a session first
    await page.getByLabel(/scenario/i).selectOption('forgery');
    await page.getByLabel(/rounds/i).fill('800');
    await page.getByLabel(/backend/i).selectOption('analytic');
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Wait for verdict badge (scoped: the verdict panel table also contains REJECT text)
    await expect(page.locator('span.badge', { hasText: /REJECT/i })).toBeVisible({ timeout: 30000 });
    
    // Record the displayed attribution (the session id itself is not rendered;
    // a replay must attribute the same attack on the same transcript)
    const attributionBefore = await page.locator('div.attribution').textContent();
    
    // Click resubmit
    await page.getByRole('button', { name: /resubmit last/i }).click();
    
    // Wait for verdict again
    await expect(page.locator('span.badge', { hasText: /REJECT/i })).toBeVisible({ timeout: 30000 });
    
    // Check attribution is unchanged (same transcript replayed)
    const attributionAfter = await page.locator('div.attribution').textContent();
    expect(attributionAfter).toBe(attributionBefore);
    
    // Evidence chart should still be visible
    await expect(page.getByRole('img')).toBeVisible();
  });
});