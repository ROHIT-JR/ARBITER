import { test, expect } from '@playwright/test';
import { injectAxe, checkA11y } from '@axe-core/playwright';

test.describe('Accessibility', () => {
  test('main page has no serious or critical violations', async ({ page }) => {
    await page.goto('/');
    await injectAxe(page);
    await checkA11y(page, undefined, {
      detailedReport: true,
      includedImpacts: ['critical', 'serious'],
    });
  });
  
  test('verdict panel has no serious or critical violations', async ({ page }) => {
    await page.goto('/');
    
    // Run a session to show verdict
    await page.getByLabelText(/scenario/i).selectOption('forgery');
    await page.getByLabelText(/rounds/i).fill('100');
    await page.getByRole('button', { name: /run session/i }).click();
    
    await expect(page.getByText(/REJECT/i)).toBeVisible({ timeout: 30000 });
    
    await injectAxe(page);
    await checkA11y(page, undefined, {
      detailedReport: true,
      includedImpacts: ['critical', 'serious'],
    });
  });
});