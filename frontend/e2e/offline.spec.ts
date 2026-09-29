import { test, expect } from '@playwright/test';

test.describe('API offline state', () => {
  test('shows offline banner when API unreachable', async ({ page }) => {
    await page.goto('/');
    
    // Intercept API calls and make them fail
    await page.route('**/api/**', route => route.abort('failed'));
    
    // Try to run a session
    await page.getByLabel(/scenario/i).selectOption('legitimate');
    await page.getByLabel(/rounds/i).fill('100');
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Should show the API error (UNREACHABLE message in the alert region)
    await expect(page.getByRole('alert')).toContainText(/Cannot reach the ARBITER API/i, { timeout: 10000 });
  });
});