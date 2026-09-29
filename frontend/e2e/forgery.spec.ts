import { test, expect } from '@playwright/test';

test.describe('Forgery session', () => {
  test('run forgery session shows REJECT with correct attribution', async ({ page }) => {
    await page.goto('/');
    
    // Wait for page to load
    await expect(page.getByRole('button', { name: /run session/i })).toBeVisible();
    
    // Select forgery hypothesis
    await page.getByLabelText(/scenario/i).selectOption('forgery');
    
    // Set rounds
    await page.getByLabelText(/rounds/i).fill('1200');
    
    // Select backend
    await page.getByLabelText(/backend/i).selectOption('analytic');
    
    // Run session
    await page.getByRole('button', { name: /run session/i }).click();
    
    // Wait for verdict
    await expect(page.getByText(/REJECT/i)).toBeVisible({ timeout: 30000 });
    
    // Check attribution
    await expect(page.getByText(/attribution: forgery/i)).toBeVisible();
    
    // Check evidence chart rendered
    await expect(page.getByRole('img')).toBeVisible();
  });
});