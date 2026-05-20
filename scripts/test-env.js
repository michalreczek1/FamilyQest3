process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-change-only-if-needed-32chars';
process.env.CHILD_CODE_PEPPER = process.env.CHILD_CODE_PEPPER || 'test-child-code-pepper-change-only-if-needed-32chars';
process.env.CHILD_JWT_EXPIRES_IN = process.env.CHILD_JWT_EXPIRES_IN || '24h';
process.env.BCRYPT_ROUNDS = process.env.BCRYPT_ROUNDS || '4';
process.env.CORS_ORIGINS = process.env.CORS_ORIGINS || 'http://127.0.0.1:3011,http://localhost:3011';
process.env.ALLOW_PUBLIC_REGISTRATION = process.env.ALLOW_PUBLIC_REGISTRATION || 'true';
