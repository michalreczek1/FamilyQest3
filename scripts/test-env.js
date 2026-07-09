// Jest loads this after dotenv. Override local/prod placeholders deliberately so
// importing the server in a test never depends on a developer's .env secrets.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-change-only-if-needed-32chars';
process.env.CHILD_CODE_PEPPER = 'test-child-code-pepper-change-only-if-needed-32chars';
process.env.CHILD_JWT_EXPIRES_IN = '24h';
process.env.BCRYPT_ROUNDS = '4';
process.env.CORS_ORIGINS = 'http://127.0.0.1:3011,http://localhost:3011';
process.env.ALLOW_PUBLIC_REGISTRATION = 'true';

// `npm test` must never silently use a developer or production database loaded
// from .env. The integration runner supplies the dedicated familyquest_test URL.
if (!/\/familyquest_test(?:\?|$)/.test(process.env.DATABASE_URL || '')) {
  delete process.env.DATABASE_URL;
}
