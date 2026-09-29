import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Accessibility', () => {
  test('main page has no serious or critical violations', async ({ page }) => {
    await page.goto('/');
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();
    const seriousOrCritical = results.violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious'
    );
    expect(seriousOrCritical).toEqual([]);
  });

  test('verdict panel has no serious or critical violations', async ({ page }) => {
    await page.goto('/');

    // Run a session to show verdict
    await page.getByLabelText(/scenario/i).selectOption('forgery');
    await page.getByLabelText(/rounds/i).fill('100');
    await page.getByRole('button', { name: /run session/i }).click();

    await expect(page.getByText(/REJECT/i)).toBeVisible({ timeout: 30000 });

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();
    const seriousOrCritical = results.violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious'
    );
    expect(seriousOrCritical).toEqual([]);
  });
});