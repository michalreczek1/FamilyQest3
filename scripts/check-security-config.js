const assert = require('assert');
const { spawnSync } = require('child_process');
const request = require('supertest');

const baseEnv = {
  ...process.env,
  NODE_ENV: 'test',
  DATABASE_URL: process.env.DATABASE_URL || 'postgresql://user:password@127.0.0.1:5432/familyquest_test?schema=public',
  JWT_SECRET: 'security-config-test-jwt-secret-32chars',
  CHILD_CODE_PEPPER: 'security-config-test-child-pepper-32chars',
  CORS_ORIGINS: 'http://127.0.0.1:3011',
};

const runRequireServer = (envOverrides) =>
  spawnSync(process.execPath, ['-e', "require('./server')"], {
    cwd: process.cwd(),
    env: {
      ...baseEnv,
      ...envOverrides,
    },
    encoding: 'utf8',
  });

const expectRequireFailure = (name, envOverrides, expectedMessage) => {
  const result = runRequireServer(envOverrides);
  assert.notStrictEqual(result.status, 0, `${name} should fail server startup`);
  assert(
    `${result.stderr}\n${result.stdout}`.includes(expectedMessage),
    `${name} should mention "${expectedMessage}"`,
  );
};

const expectRequireSuccess = (name, envOverrides) => {
  const result = runRequireServer(envOverrides);
  assert.strictEqual(result.status, 0, `${name} should allow server import: ${result.stderr || result.stdout}`);
};

const run = async () => {
  expectRequireFailure('missing JWT_SECRET', { JWT_SECRET: '' }, 'JWT_SECRET');
  expectRequireFailure('missing CHILD_CODE_PEPPER', { CHILD_CODE_PEPPER: '' }, 'CHILD_CODE_PEPPER');
  expectRequireFailure('default JWT_SECRET', { JWT_SECRET: 'dev-only-change-me-in-production' }, 'JWT_SECRET');
  expectRequireFailure('wildcard CORS', { CORS_ORIGINS: '*' }, 'CORS_ORIGINS=*');
  expectRequireSuccess('production debug flag gated', {
    NODE_ENV: 'production',
    ALLOW_DEBUG_RESET_TOKEN: 'true',
  });

  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = baseEnv.JWT_SECRET;
  process.env.CHILD_CODE_PEPPER = baseEnv.CHILD_CODE_PEPPER;
  process.env.CORS_ORIGINS = baseEnv.CORS_ORIGINS;
  delete process.env.ALLOW_PUBLIC_REGISTRATION;
  const { app, prisma } = require('../server');
  const registrationRes = await request(app)
    .post('/api/auth/register')
    .send({
      email: 'security-config@example.local',
      password: 'SecurityPass123!',
      pinCode: '246813',
      familyName: 'Security Config',
    });
  assert.strictEqual(registrationRes.status, 403, 'public registration should default to disabled');
  await prisma.$disconnect();
};

run()
  .then(() => {
    console.log('Security config checks passed.');
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
