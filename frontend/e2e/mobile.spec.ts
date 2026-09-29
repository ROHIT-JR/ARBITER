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
    
    // Check form labels are visible and not overlapping
    const labels = page.locator('label');
    const count = await labels.count();
    expect(count).toBeGreaterThan(0);
    
    // Run a quick session to check verdict panel
    await page.getByLabel(/scenario/i).selectOption('legitimate');
    await page.getByLabel(/rounds/i).fill('100');
    await page.getByRole('button', { name: /run session/i }).click();
    
    await expect(page.getByText(/ACCEPT/i)).toBeVisible({ timeout: 30000 });
    
    // Check verdict panel renders without horizontal overflow
    const verdictWidth = await page.evaluate(() => document.body.scrollWidth);
    expect(verdictWidth).toBeLessThanOrEqual(375);
  });
});