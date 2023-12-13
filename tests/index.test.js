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