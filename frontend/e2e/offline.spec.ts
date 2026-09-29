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
    
    // Should show the API error. Several panels independently fetch and
    // render the same UNREACHABLE text in a plain <p class="error">
    // (AccuracyPanel, BoundsTable, LedgerPanel, DemoMenu), so a bare
    // p.error match is ambiguous. Only the session-run error's own <p>
    // carries role="alert" directly (the others put role="alert" on a
    // *wrapping* element, not the <p> itself) -- scope to that.
    await expect(
      page.locator('p.error[role="alert"]', { hasText: /Cannot reach the ARBITER API/i })
    ).toBeVisible({
      timeout: 10000,
    });
  });
});