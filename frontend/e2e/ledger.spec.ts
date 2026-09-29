import { test, expect } from '@playwright/test';

test.describe('Ledger verification', () => {
  test('verify ledger shows OK', async ({ page }) => {
    await page.goto('/');
    
    // Run a session to generate ledger entry
    await page.getByLabelText(/scenario/i).selectOption('legitimate');
    await page.getByLabelText(/rounds/i).fill('100');
    await page.getByLabelText(/backend/i).selectOption('analytic');
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Wait for verdict
    await expect(page.getByText(/ACCEPT/i)).toBeVisible({ timeout: 30000 });
    
    // Click verify ledger
    await page.getByRole('button', { name: /verify ledger/i }).click();
    
    // Wait for verification result
    await expect(page.getByText(/✓ ledger ok/i)).toBeVisible({ timeout: 10000 });
  });
});