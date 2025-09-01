import { test, expect } from '@playwright/test';

test.describe('API Health Check', () => {
  test('should verify API is accessible', async ({ request }) => {
    const response = await request.get('/');
    
    expect(response.ok()).toBeTruthy();
    expect(response.status()).toBe(200);
    
    const body = await response.json();
    expect(body).toHaveProperty('message');
    
    console.log('✅ API is healthy and responding');
  });
  
  test('should return correct headers', async ({ request }) => {
    const response = await request.get('/');
    
    const headers = response.headers();
    expect(headers).toHaveProperty('content-type');
    expect(headers['content-type']).toContain('application/json');
  });
});