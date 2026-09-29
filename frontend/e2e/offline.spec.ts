import { test, expect } from '@playwright/test';

test.describe('API offline state', () => {
  test('shows offline banner when API unreachable', async ({ page }) => {
    await page.goto('/');
    
    // Intercept API calls and make them fail
    await page.route('**/api/**', route => route.abort('failed'));
    
    // Try to run a session
    await page.getByLabelText(/scenario/i).selectOption('legitimate');
    await page.getByLabelText(/rounds/i).fill('100');
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Should show offline message
    await expect(page.getByText(/cannot reach api/i)).toBeVisible({ timeout: 10000 });
  });
});