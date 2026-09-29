import { test, expect } from '@playwright/test';

test.describe('Ledger verification', () => {
  test('verify ledger shows OK', async ({ page }) => {
    await page.goto('/');
    
    // Run a session to generate ledger entry (pinned seed: unseeded 100-round
    // legitimate sessions false-alarm often enough to flake this flow test)
    await page.getByLabel(/scenario/i).selectOption('legitimate');
    await page.getByLabel(/rounds/i).fill('100');
    await page.getByLabel(/backend/i).selectOption('analytic');
    await page.getByLabel(/seed/i).fill('7');
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Wait for verdict badge (scoped: the verdict panel table also contains ACCEPT text)
    await expect(page.locator('span.badge', { hasText: /ACCEPT/i })).toBeVisible({ timeout: 60000 });
    
    // Click verify (button is labeled "Verify chain")
    await page.getByRole('button', { name: /verify chain/i }).click();
    
    // Wait for verification result (LedgerPanel renders "✓ N entries valid")
    await expect(page.getByText(/entries valid/i)).toBeVisible({ timeout: 10000 });
  });
});