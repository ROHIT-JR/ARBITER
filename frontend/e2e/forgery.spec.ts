import { test, expect } from '@playwright/test';

test.describe('Forgery session', () => {
  // A 1200-round analytic session plus calibration Monte Carlo can exceed
  // the 30s default on shared CI runners.
  test.slow();
  test('run forgery session shows REJECT with correct attribution', async ({ page }) => {
    await page.goto('/');
    
    // Wait for page to load
    await expect(page.getByRole('button', { name: /run session/i })).toBeVisible();
    
    // Select forgery hypothesis
    await page.getByLabel(/scenario/i).selectOption('forgery');
    
    // Set rounds
    await page.getByLabel(/rounds/i).fill('1200');
    
    // Select backend
    await page.getByLabel(/backend/i).selectOption('analytic');
    
    // Run session
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Wait for verdict badge (scoped: the verdict panel table also contains REJECT text)
    await expect(page.locator('span.badge', { hasText: /REJECT/i })).toBeVisible({ timeout: 30000 });
    
    // Check attribution (rendered as a bare label in div.attribution)
    await expect(page.locator('div.attribution', { hasText: /forgery/i })).toBeVisible();
    
    // Check evidence chart rendered
    await expect(page.getByRole('img')).toBeVisible();
  });
});