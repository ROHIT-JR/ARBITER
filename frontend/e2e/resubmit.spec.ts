import { test, expect } from '@playwright/test';

test.describe('Resubmit replay', () => {
  test('resubmit preserves session and evidence chart', async ({ page }) => {
    await page.goto('/');
    
    // Run a session first
    await page.getByLabel(/scenario/i).selectOption('forgery');
    await page.getByLabel(/rounds/i).fill('800');
    await page.getByLabel(/backend/i).selectOption('analytic');
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Wait for verdict
    await expect(page.getByText(/REJECT/i)).toBeVisible({ timeout: 30000 });
    
    // Get session ID
    const sessionIdBefore = await page.getByText(/session:/i).textContent();
    
    // Click resubmit
    await page.getByRole('button', { name: /resubmit last/i }).click();
    
    // Wait for verdict again
    await expect(page.getByText(/REJECT/i)).toBeVisible({ timeout: 30000 });
    
    // Check session ID is the same (replay)
    const sessionIdAfter = await page.getByText(/session:/i).textContent();
    expect(sessionIdAfter).toBe(sessionIdBefore);
    
    // Evidence chart should still be visible
    await expect(page.getByRole('img')).toBeVisible();
  });
});