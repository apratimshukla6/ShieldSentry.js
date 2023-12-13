// tests/index.test.js
const ShieldSentry = require('../src/shieldsentry');
const sentry = new ShieldSentry();

test('sanitizes SQL input', () => {
  const input = "\" OR \"1\"=\"1";
  const sanitized = sentry.sqlEscape(input);
  expect(sanitized).toBe("\\\" OR \\\"1\\\"=\\\"1");
});

test('sanitizes XSS input', () => {
  const input = "<script>alert('XSS')</script>";
  const sanitized = sentry.htmlEscape(input);
  expect(sanitized).toBe("&amp;lt;script&amp;gt;alert(&#x27;XSS&#x27;)&amp;lt;&#x2F;script&amp;gt;");
});

describe('Access Control Tests', () => {
    test('admin should have all permissions', () => {
      expect(sentry.hasPermission('admin', 'write')).toBe(true);
      expect(sentry.hasPermission('admin', 'read')).toBe(true);
    });
  
    test('user should have read and write permissions', () => {
      expect(sentry.hasPermission('user', 'read')).toBe(true);
      expect(sentry.hasPermission('user', 'write')).toBe(true);
    });
  
    test('guest should have only read permission', () => {
      expect(sentry.hasPermission('guest', 'read')).toBe(true);
      expect(sentry.hasPermission('guest', 'write')).toBe(false);
    });
  
    test('invalid role should not have any permissions', () => {
      expect(sentry.hasPermission('invalid_role', 'read')).toBe(false);
      expect(sentry.hasPermission('invalid_role', 'write')).toBe(false);
    });
});

describe('API Rate Limiting and Quota Tests', () => {
    jest.setTimeout(300000);
    let sentry;
    const userId = 'testUser';
  
    beforeEach(() => {
      sentry = new ShieldSentry();
      sentry.rateLimiting = {
        maxRequestsPerMinute: 60,
        quotaThreshold: 1000
      };
    });
  
    test('should allow initial requests under rate limit', () => {
      for (let i = 0; i < 60; i++) {
        expect(sentry.isRateLimited(userId)).toBe(false);
      }
    });
  
    test('should rate limit after exceeding maxRequestsPerMinute', () => {
      for (let i = 0; i < 60; i++) {
        sentry.isRateLimited(userId);
      }
      expect(sentry.isRateLimited(userId)).toBe(true);
    });
  
    test('should not rate limit after reset time', async () => {
      for (let i = 0; i < 60; i++) {
        sentry.isRateLimited(userId);
      }
  
      // Simulating time passing for rate limit reset
      await new Promise(r => setTimeout(r, 60000));
      expect(sentry.isRateLimited(userId)).toBe(false);
    });
  
    test('should enforce quota threshold', () => {
      for (let i = 0; i < 1000; i++) {
        sentry.isRateLimited(userId);
      }
      // 1001st request should be blocked due to quota
      expect(sentry.isRateLimited(userId)).toBe(true);
    });
});
  