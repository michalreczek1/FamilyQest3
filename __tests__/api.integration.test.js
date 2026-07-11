require('dotenv').config();
require('../scripts/test-env');
process.env.ALLOW_DEBUG_RESET_TOKEN = 'true';
process.env.ALLOW_PUBLIC_REGISTRATION = 'true';

const request = require('supertest');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { app, prisma, __test } = require('../server');

const hasDatabase = Boolean(process.env.DATABASE_URL);

const maybeDescribe = hasDatabase ? describe : describe.skip;
const TEST_PARENT_PASSWORD = 'TestParentPass123!';
const TEST_RESET_PASSWORD = 'TestResetPass999!';

const createParentPayload = (suffix) => ({
  email: `jest.parent.${suffix}@familyquest.local`,
  password: TEST_PARENT_PASSWORD,
  pinCode: '246813',
  familyName: 'Jest Rodzina',
});

const getToday = () => new Date().toISOString().slice(0, 10);

const makeBackupState = (overrides = {}) => ({
  children: [],
  tasks: [],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  pointLedger: [],
  rewards: [],
  streaks: {},
  points: {},
  rewardUnlocks: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
  ...overrides,
});

const registerParent = async (suffix) => {
  const registerRes = await request(app).post('/api/auth/register').send(createParentPayload(suffix));
  expect(registerRes.status).toBe(201);
  return registerRes.body.token;
};

const restoreFamilyState = async (parentToken, state) => {
  const restoreRes = await request(app)
    .post('/api/storage/restore-backup')
    .set('Authorization', `Bearer ${parentToken}`)
    .send({ backup: makeBackupState(state) });
  expect(restoreRes.status).toBe(200);
  return restoreRes.body;
};

maybeDescribe('FamilyQuest API integration', () => {
  jest.setTimeout(60000);

test('storage sanitizer strips child access codes from children and audit logs', () => {
    const sanitized = __test.sanitizeStateDataForStorage(makeBackupState({
      children: [{ id: 'child-a', name: 'A', avatar: '⭐', activeDays: [1], accessCode: '1234' }],
      auditLogs: [{ id: 'audit-a', action: 'UPDATE_CHILD', details: { accessCode: '1234', name: 'A' } }],
    }));
    expect(sanitized.children[0]).not.toHaveProperty('accessCode');
    expect(sanitized.auditLogs[0].details).not.toHaveProperty('accessCode');
    expect(sanitized.auditLogs[0].details.accessCodeChanged).toBe(true);
  });

  test('date helpers keep YYYY-MM-DD stable across supported time zones', () => {
    for (const timezone of ['UTC', 'Europe/Warsaw']) {
      const script = `
        require('./scripts/test-env');
        const { __test, prisma } = require('./server');
        const assert = require('assert');
        assert.strictEqual(__test.toDateString('2026-03-29'), '2026-03-29');
        assert.strictEqual(__test.isValidDateString('2026-03-29'), true);
        assert.strictEqual(__test.getDayNumber('2026-03-30'), 1);
        prisma.$disconnect().then(() => process.exit(0));
      `;
      const result = spawnSync(process.execPath, ['-e', script], {
        cwd: process.cwd(),
        env: { ...process.env, TZ: timezone },
        encoding: 'utf8',
      });
      expect(result.status).toBe(0);
    }
  });

  test('JWT revocation and child credential binding invalidate stale sessions', async () => {
    const suffix = `jwt-hardening-${Date.now()}`;
    const parentPayload = createParentPayload(suffix);
    const registerRes = await request(app).post('/api/auth/register').send(parentPayload);
    expect(registerRes.status).toBe(201);
    const parentToken = registerRes.body.token;
    const decodedParentToken = jwt.decode(parentToken);
    expect(decodedParentToken.jti).toBeTruthy();

    const legacyParentToken = jwt.sign(
      {
        sub: registerRes.body.user.id,
        familyId: registerRes.body.user.familyId,
        role: 'PARENT',
        tokenType: 'USER',
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' },
    );
    const legacyMeRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${legacyParentToken}`);
    expect(legacyMeRes.status).toBe(401);

    const parentMeRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(parentMeRes.status).toBe(200);

    const parentLogoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(parentLogoutRes.status).toBe(200);
    const parentAfterLogoutRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(parentAfterLogoutRes.status).toBe(401);

    const secondParentToken = await registerParent(`${suffix}-child`);
    const childRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${secondParentToken}`)
      .send({
        name: `Tokeny-${suffix}`,
        avatar: '⭐',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(childRes.status).toBe(201);
    const child = childRes.body.child;
    const childLoginRes = await request(app)
      .post('/api/auth/login-child')
      .send({ accessCode: child.accessCode });
    expect(childLoginRes.status).toBe(200);
    const childToken = childLoginRes.body.token;
    const decodedChildToken = jwt.decode(childToken);
    expect(decodedChildToken.jti).toBeTruthy();
    expect(decodedChildToken.credentialId).toBeTruthy();

    let newChildCode = null;
    for (let i = 0; i < 50; i += 1) {
      const candidate = String(((Date.now() + i) % 9000) + 1000);
      if (candidate === child.accessCode) continue;
      const updateCodeRes = await request(app)
        .put(`/api/children/${child.id}`)
        .set('Authorization', `Bearer ${secondParentToken}`)
        .send({ accessCode: candidate });
      if (updateCodeRes.status === 200) {
        newChildCode = updateCodeRes.body.child.accessCode;
        break;
      }
      expect(updateCodeRes.status).toBe(409);
    }
    expect(newChildCode).toMatch(/^\d{4}$/);

    const staleChildMeRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${childToken}`);
    expect(staleChildMeRes.status).toBe(401);

    const newChildLoginRes = await request(app)
      .post('/api/auth/login-child')
      .send({ accessCode: newChildCode });
    expect(newChildLoginRes.status).toBe(200);
    const childLogoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${newChildLoginRes.body.token}`);
    expect(childLogoutRes.status).toBe(200);
    const childAfterLogoutRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${newChildLoginRes.body.token}`);
    expect(childAfterLogoutRes.status).toBe(401);
  });

  test('family snapshot is role-filtered, versioned and supports ETag revalidation', async () => {
    const suffix = `snapshot-${Date.now()}`;
    const registerRes = await request(app).post('/api/auth/register').send(createParentPayload(suffix));
    expect(registerRes.status).toBe(201);
    const parentToken = registerRes.body.token;
    expect(registerRes.body.user.sessionRef).toBe(jwt.decode(parentToken).jti);

    const snapshotRes = await request(app)
      .get('/api/family-state')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(snapshotRes.status).toBe(200);
    expect(snapshotRes.body.familyId).toBe(registerRes.body.user.familyId);
    expect(snapshotRes.body.version).toBe(0);
    expect(snapshotRes.body.viewer.sessionRef).toBe(jwt.decode(parentToken).jti);
    expect(snapshotRes.body.family).toHaveProperty('children');
    expect(snapshotRes.headers.etag).toContain(`family-${registerRes.body.user.familyId}`);

    const notModified = await request(app)
      .get('/api/family-state')
      .set('Authorization', `Bearer ${parentToken}`)
      .set('If-None-Match', snapshotRes.headers.etag);
    expect(notModified.status).toBe(304);

    const metricsRes = await request(app)
      .get('/api/sync/metrics')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(metricsRes.status).toBe(200);
    expect(metricsRes.body.metrics.snapshot_success).toBeGreaterThanOrEqual(1);
    expect(metricsRes.body.metrics.snapshot_not_modified).toBeGreaterThanOrEqual(1);

    const childRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({ name: 'Czytelnik historii', avatar: '📚', activeDays: [1, 2, 3, 4, 5, 6, 7] });
    expect(childRes.status).toBe(201);
    const beforeLedger = await request(app)
      .get('/api/family-state')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(beforeLedger.status).toBe(200);

    const ledgerRes = await request(app)
      .get(`/api/point-ledger?childId=${encodeURIComponent(childRes.body.child.id)}`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(ledgerRes.status).toBe(200);

    const afterLedger = await request(app)
      .get('/api/family-state')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(afterLedger.status).toBe(200);
    expect(afterLedger.body.version).toBe(beforeLedger.body.version);
  });

  test('idempotency returns the original result and rejects key reuse with another payload', async () => {
    const parentToken = await registerParent(`idempotency-${Date.now()}`);
    const idempotencyKey = crypto.randomUUID();
    const payload = { title: 'Spójny cel', target: 333, mode: 'points' };
    const first = await request(app)
      .put('/api/family-goal')
      .set('Authorization', `Bearer ${parentToken}`)
      .set('Idempotency-Key', idempotencyKey)
      .send(payload);
    expect(first.status).toBe(200);
    expect(Number.isInteger(first.body.version)).toBe(true);

    const repeated = await request(app)
      .put('/api/family-goal')
      .set('Authorization', `Bearer ${parentToken}`)
      .set('Idempotency-Key', idempotencyKey)
      .send(payload);
    expect(repeated.status).toBe(200);
    expect(repeated.body).toEqual(first.body);

    const reused = await request(app)
      .put('/api/family-goal')
      .set('Authorization', `Bearer ${parentToken}`)
      .set('Idempotency-Key', idempotencyKey)
      .send({ ...payload, target: 444 });
    expect(reused.status).toBe(409);
    expect(reused.body.code).toBe('IDEMPOTENCY_KEY_REUSED');
  });

  test('atomic idempotency commits one family mutation and replays it to concurrent callers', async () => {
    const registerRes = await request(app)
      .post('/api/auth/register')
      .send(createParentPayload(`atomic-idempotency-${Date.now()}`));
    expect(registerRes.status).toBe(201);
    const idempotencyKey = crypto.randomUUID();
    const payload = {
      name: 'Jednorazowe dziecko',
      avatar: '🦊',
      activeDays: [1, 2, 3, 4, 5],
    };

    const send = () => request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .set('Idempotency-Key', idempotencyKey)
      .send(payload);
    const [first, second] = await Promise.all([send(), send()]);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(second.body).toEqual(first.body);
    expect(Number.isInteger(first.body.version)).toBe(true);

    const childrenRes = await request(app)
      .get('/api/children')
      .set('Authorization', `Bearer ${registerRes.body.token}`);
    expect(childrenRes.status).toBe(200);
    expect(childrenRes.body.children.filter((child) => child.name === payload.name)).toHaveLength(1);

    const persisted = await prisma.idempotencyOperation.findUnique({
      where: {
        userId_familyId_operationCode_idempotencyKey: {
          userId: registerRes.body.user.id,
          familyId: registerRes.body.user.familyId,
          operationCode: 'POST:/children',
          idempotencyKey,
        },
      },
    });
    expect(persisted?.completedAt).toBeTruthy();
    expect(persisted?.responseStatus).toBe(201);
    expect(persisted?.responseBody).toEqual(first.body);
  });

  test('atomic idempotency creates one child completion for concurrent retries', async () => {
    const parentToken = await registerParent(`atomic-completion-${Date.now()}`);
    const childRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({ name: 'Maja', avatar: '🦉', activeDays: [1, 2, 3, 4, 5, 6, 7] });
    expect(childRes.status).toBe(201);
    const taskRes = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({ childId: childRes.body.child.id, title: 'Wynieś śmieci', tier: 'MIN', points: 2 });
    expect(taskRes.status).toBe(201);

    const idempotencyKey = crypto.randomUUID();
    const payload = {
      childId: childRes.body.child.id,
      taskId: taskRes.body.task.id,
      date: getToday(),
      doneByChild: true,
    };
    const send = () => request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${parentToken}`)
      .set('Idempotency-Key', idempotencyKey)
      .send(payload);
    const [first, second] = await Promise.all([send(), send()]);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(second.body).toEqual(first.body);

    const completionsRes = await request(app)
      .get(`/api/completions?childId=${encodeURIComponent(payload.childId)}&date=${payload.date}`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(completionsRes.status).toBe(200);
    expect(completionsRes.body.completions).toHaveLength(1);
    expect(completionsRes.body.completions[0].id).toBe(first.body.completion.id);
  });

  test('idempotency bounds waiting for an unresolved competing operation', async () => {
    const suffix = `idempotency-pending-${Date.now()}`;
    const registerRes = await request(app).post('/api/auth/register').send(createParentPayload(suffix));
    expect(registerRes.status).toBe(201);
    const payload = { title: 'Cel oczekujący', target: 123, mode: 'points' };
    const idempotencyKey = crypto.randomUUID();
    await prisma.idempotencyOperation.create({
      data: {
        userId: registerRes.body.user.id,
        familyId: registerRes.body.user.familyId,
        operationCode: 'PUT:/family-goal',
        idempotencyKey,
        requestHash: crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex'),
        expiresAt: new Date(Date.now() + 60000),
      },
    });
    const result = await request(app)
      .put('/api/family-goal')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .set('Idempotency-Key', idempotencyKey)
      .send(payload);
    expect(result.status).toBe(409);
    expect(result.headers['retry-after']).toBe('2');
    expect(result.body.code).toBe('IDEMPOTENCY_RESULT_PENDING');
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  test('parent/child flow, approvals and password reset token', async () => {
    const suffix = Date.now();
    const parentPayload = createParentPayload(suffix);
    const childName = `Dziecko-${suffix}`;
    const today = getToday();

    const registerRes = await request(app).post('/api/auth/register').send(parentPayload);
    expect(registerRes.status).toBe(201);
    expect(registerRes.body.token).toBeTruthy();
    expect(registerRes.body.user.email).toBe(parentPayload.email);
    expect(registerRes.body.user).not.toHaveProperty('pinCode');
    expect(registerRes.body.user.hasPinCode).toBe(true);

    const invalidParentPinRes = await request(app)
      .post('/api/auth/parent-pin/verify')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .send({ pinCode: '111111' });
    expect(invalidParentPinRes.status).toBe(401);

    const validParentPinRes = await request(app)
      .post('/api/auth/parent-pin/verify')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .send({ pinCode: parentPayload.pinCode });
    expect(validParentPinRes.status).toBe(200);

    const shortParentPinRes = await request(app)
      .put('/api/auth/pin')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .send({ currentPassword: parentPayload.password, pinCode: '1234' });
    expect(shortParentPinRes.status).toBe(400);

    const changedParentPinRes = await request(app)
      .put('/api/auth/pin')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .send({ currentPassword: parentPayload.password, pinCode: '135790' });
    expect(changedParentPinRes.status).toBe(200);
    expect(changedParentPinRes.body.user.hasPinCode).toBe(true);

    const firstBadPinRes = await request(app)
      .post('/api/auth/parent-pin/verify')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .send({ pinCode: '000000' });
    expect(firstBadPinRes.status).toBe(401);
    expect(firstBadPinRes.body.attemptsRemaining).toBe(2);

    const secondBadPinRes = await request(app)
      .post('/api/auth/parent-pin/verify')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .send({ pinCode: '000000' });
    expect(secondBadPinRes.status).toBe(401);
    expect(secondBadPinRes.body.attemptsRemaining).toBe(1);

    const lockedPinRes = await request(app)
      .post('/api/auth/parent-pin/verify')
      .set('Authorization', `Bearer ${registerRes.body.token}`)
      .send({ pinCode: '000000' });
    expect(lockedPinRes.status).toBe(429);
    expect(lockedPinRes.body.retryAfterSeconds).toBeGreaterThan(0);

    const parentToken = registerRes.body.token;
    const csrfGuardRes = await request(app)
      .post('/api/tasks')
      .set('Cookie', registerRes.headers['set-cookie'] || [])
      .send({
        childId: 'missing',
        title: 'Bez nagłówka',
        tier: 'MIN',
        points: 1,
      });
    expect(csrfGuardRes.status).toBe(403);

    const addChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        name: childName,
        avatar: '🦊',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(addChildRes.status).toBe(201);
    expect(addChildRes.body.child.id).toBeTruthy();
    expect(addChildRes.body.child.accessCode).toMatch(/^\d{4}$/);

    const child = addChildRes.body.child;
    const familyStateAfterChildCreate = await prisma.familyState.findUnique({
      where: { familyId: registerRes.body.user.familyId },
    });
    expect(JSON.stringify(familyStateAfterChildCreate.data)).not.toContain(child.accessCode);
    const siblingName = `Rodzenstwo-${suffix}`;
    const addSiblingRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        name: siblingName,
        avatar: '🐼',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(addSiblingRes.status).toBe(201);
    const sibling = addSiblingRes.body.child;
    const addThirdChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        name: `Trzecie-${suffix}`,
        avatar: '🦁',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(addThirdChildRes.status).toBe(201);
    const thirdChild = addThirdChildRes.body.child;

    const addFourthChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        name: `Czwarte-${suffix}`,
        avatar: '🐸',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(addFourthChildRes.status).toBe(201);
    const fourthChild = addFourthChildRes.body.child;

    let loginCode = null;
    for (let i = 0; i < 50; i += 1) {
      const candidate = String(((suffix + i) % 9000) + 1000);
      const setCodeRes = await request(app)
        .put(`/api/children/${child.id}`)
        .set('Authorization', `Bearer ${parentToken}`)
        .send({ accessCode: candidate });

      if (setCodeRes.status === 200) {
        loginCode = setCodeRes.body?.child?.accessCode || candidate;
        break;
      }
      if (setCodeRes.status !== 409) {
        throw new Error(`Unexpected status while setting child access code: ${setCodeRes.status}`);
      }
    }
    expect(loginCode).toBeTruthy();

    const addTaskRes = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        title: 'Pościel łóżko',
        tier: 'MIN',
        points: 3,
        description: 'Rano po wstaniu',
      });
    expect(addTaskRes.status).toBe(201);
    expect(addTaskRes.body.task.id).toBeTruthy();

    const task = addTaskRes.body.task;

    const childLoginRes = await request(app).post('/api/auth/login-child').send({
      accessCode: loginCode,
    });
    expect(childLoginRes.status).toBe(200);
    expect(childLoginRes.body.token).toBeTruthy();
    expect(childLoginRes.body.user.role).toBe('CHILD');
    const decodedChildToken = jwt.decode(childLoginRes.body.token);
    expect(decodedChildToken.exp - decodedChildToken.iat).toBeLessThanOrEqual(24 * 60 * 60);

    const childToken = childLoginRes.body.token;

    const familyChildCodes = [
      sibling.accessCode,
      thirdChild.accessCode,
      fourthChild.accessCode,
    ];
    for (const accessCode of familyChildCodes) {
      const sequentialChildLoginRes = await request(app).post('/api/auth/login-child').send({
        accessCode,
      });
      expect(sequentialChildLoginRes.status).toBe(200);
      expect(sequentialChildLoginRes.body.user.role).toBe('CHILD');
    }

    const childForbiddenRes = await request(app)
      .get('/api/auth/parents')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childForbiddenRes.status).toBe(403);

    const childStorageChildrenRes = await request(app)
      .get('/api/storage/get/children')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childStorageChildrenRes.status).toBe(200);
    expect(childStorageChildrenRes.body.value).toHaveLength(1);
    expect(childStorageChildrenRes.body.value[0].id).toBe(child.id);
    expect(childStorageChildrenRes.body.value[0]).not.toHaveProperty('accessCode');
    expect(childStorageChildrenRes.body.value.some((item) => item.id === sibling.id)).toBe(false);

    const childStorageAuditRes = await request(app)
      .get('/api/storage/get/auditLogs')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childStorageAuditRes.status).toBe(200);
    expect(childStorageAuditRes.body.value).toEqual([]);

    const childLeaderboardRes = await request(app)
      .get('/api/leaderboard')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childLeaderboardRes.status).toBe(200);
    expect(childLeaderboardRes.body.children.some((item) => item.id === child.id)).toBe(true);
    expect(childLeaderboardRes.body.children.some((item) => item.id === sibling.id)).toBe(true);
    expect(childLeaderboardRes.body.children.some((item) => Object.prototype.hasOwnProperty.call(item, 'accessCode'))).toBe(false);

    const childStorageMergeRes = await request(app)
      .post('/api/storage/merge')
      .set('Authorization', `Bearer ${childToken}`)
      .send({
        values: {
          children: [{ id: sibling.id, name: 'Nie powinno przejsc' }],
          auditLogs: [{ id: 'fake-audit' }],
          completions: [
            {
              id: 'storage-own-completion',
              taskId: task.id,
              childId: child.id,
              date: today,
              doneByChild: true,
              approvedByParent: false,
            },
            {
              id: 'storage-sibling-completion',
              taskId: task.id,
              childId: sibling.id,
              date: today,
              doneByChild: true,
              approvedByParent: false,
            },
          ],
        },
      });
    expect(childStorageMergeRes.status).toBe(200);

    const staleParentMergeRes = await request(app)
      .post('/api/storage/merge')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        values: {
          completions: [],
          points: { [child.id]: 0 },
        },
      });
    expect(staleParentMergeRes.status).toBe(200);

    const invalidPendingMergeRes = await request(app)
      .post('/api/storage/merge')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        values: {
          completions: [
            {
              id: 'storage-invalid-past-completion',
              taskId: task.id,
              childId: child.id,
              date: '2000-01-01',
              doneByChild: true,
              approvedByParent: false,
              updatedAt: new Date().toISOString(),
            },
          ],
        },
      });
    expect(invalidPendingMergeRes.status).toBe(200);

    const parentStorageChildrenRes = await request(app)
      .get('/api/storage/get/children')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(parentStorageChildrenRes.status).toBe(200);
    expect(parentStorageChildrenRes.body.value.find((item) => item.id === sibling.id)?.name).toBe(siblingName);

    const childStorageCompletionsRes = await request(app)
      .get('/api/storage/get/completions')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childStorageCompletionsRes.status).toBe(200);
    expect(childStorageCompletionsRes.body.value.some((item) => item.id === 'storage-own-completion')).toBe(true);
    expect(childStorageCompletionsRes.body.value.some((item) => item.id === 'storage-sibling-completion')).toBe(false);
    const invalidPastCompletion = childStorageCompletionsRes.body.value.find(
      (item) => item.id === 'storage-invalid-past-completion',
    );
    expect(invalidPastCompletion.doneByChild).toBe(false);
    expect(invalidPastCompletion.approvedByParent).toBe(false);
    expect(invalidPastCompletion.rejectedByParent).toBe(true);

    const markDoneRes = await request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${childToken}`)
      .send({
        taskId: task.id,
        childId: child.id,
        date: today,
        doneByChild: true,
      });
    expect([200, 201]).toContain(markDoneRes.status);
    const completionId = markDoneRes.body.completion.id;

    const pendingRes = await request(app)
      .get('/api/completions/pending')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pendingRes.status).toBe(200);
    expect(Array.isArray(pendingRes.body.completions)).toBe(true);
    expect(pendingRes.body.completions.length).toBeGreaterThan(0);

    const bulkApproveRes = await request(app)
      .post('/api/completions/approve-bulk')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        date: today,
      });
    expect(bulkApproveRes.status).toBe(200);
    expect(bulkApproveRes.body.approvedCount).toBeGreaterThanOrEqual(1);
    expect(Number.isInteger(bulkApproveRes.body.version)).toBe(true);
    expect(bulkApproveRes.body.patch).toEqual(bulkApproveRes.body.statePatch);

    const pendingAfterBulkApproveRes = await request(app)
      .get(`/api/completions/pending?childId=${encodeURIComponent(child.id)}&date=${encodeURIComponent(today)}`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pendingAfterBulkApproveRes.status).toBe(200);
    expect(pendingAfterBulkApproveRes.body.completions.some((item) => item.id === completionId)).toBe(false);

    const pointsAfterApproveRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsAfterApproveRes.status).toBe(200);
    const pointsAfterApprove = pointsAfterApproveRes.body.value[child.id] || 0;

    const streaksAfterApproveRes = await request(app)
      .get('/api/storage/get/streaks')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(streaksAfterApproveRes.status).toBe(200);
    expect(streaksAfterApproveRes.body.value[child.id].current).toBeGreaterThanOrEqual(1);
    expect(streaksAfterApproveRes.body.value[child.id].best).toBeGreaterThanOrEqual(1);

    const duplicateApproveRes = await request(app)
      .post(`/api/completions/${completionId}/approve`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(duplicateApproveRes.status).toBe(409);

    const pointsAfterDuplicateApproveRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsAfterDuplicateApproveRes.status).toBe(200);
    expect(pointsAfterDuplicateApproveRes.body.value[child.id] || 0).toBe(pointsAfterApprove);

    const rejectTaskRes = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        title: 'Zadanie do odrzucenia zbiorczego',
        tier: 'PLUS',
        points: 1,
        description: 'Test bulk reject',
      });
    expect(rejectTaskRes.status).toBe(201);

    const markRejectDoneRes = await request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${childToken}`)
      .send({
        taskId: rejectTaskRes.body.task.id,
        childId: child.id,
        date: today,
        doneByChild: true,
      });
    expect([200, 201]).toContain(markRejectDoneRes.status);
    const rejectCompletionId = markRejectDoneRes.body.completion.id;

    const bulkRejectRes = await request(app)
      .post('/api/completions/reject-bulk')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        ids: [rejectCompletionId],
        childId: child.id,
        date: today,
      });
    expect(bulkRejectRes.status).toBe(200);
    expect(bulkRejectRes.body.rejectedCount).toBe(1);
    expect(bulkRejectRes.body.rejectedIds).toContain(rejectCompletionId);

    const pendingAfterBulkRejectRes = await request(app)
      .get(`/api/completions/pending?childId=${encodeURIComponent(child.id)}&date=${encodeURIComponent(today)}`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pendingAfterBulkRejectRes.status).toBe(200);
    expect(pendingAfterBulkRejectRes.body.completions.some((item) => item.id === rejectCompletionId)).toBe(false);

    const pointsAfterBulkRejectRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsAfterBulkRejectRes.status).toBe(200);
    expect(pointsAfterBulkRejectRes.body.value[child.id] || 0).toBe(pointsAfterApprove);

    const extraTaskRes = await request(app)
      .post('/api/extra-tasks')
      .set('Authorization', `Bearer ${childToken}`)
      .send({
        childId: child.id,
        title: 'Pomogłem wynieść śmieci',
        date: today,
      });
    expect(extraTaskRes.status).toBe(201);
    expect(extraTaskRes.body.extraTask.status).toBe('PENDING');
    expect(extraTaskRes.body.extraTask.points).toBe(1);

    const childExtraTasksRes = await request(app)
      .get('/api/storage/get/extraTasks')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childExtraTasksRes.status).toBe(200);
    expect(childExtraTasksRes.body.value.some((item) => item.id === extraTaskRes.body.extraTask.id)).toBe(true);

    const pendingExtraTaskRes = await request(app)
      .get('/api/extra-tasks?pending=true')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pendingExtraTaskRes.status).toBe(200);
    expect(pendingExtraTaskRes.body.extraTasks.some((item) => item.id === extraTaskRes.body.extraTask.id)).toBe(true);

    const approveExtraTaskRes = await request(app)
      .post(`/api/extra-tasks/${extraTaskRes.body.extraTask.id}/approve`)
      .set('Authorization', `Bearer ${parentToken}`)
      .send({ points: 7 });
    expect(approveExtraTaskRes.status).toBe(200);
    expect(approveExtraTaskRes.body.extraTask.status).toBe('APPROVED');
    expect(approveExtraTaskRes.body.extraTask.points).toBe(7);

    const pointsAfterExtraTaskRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsAfterExtraTaskRes.status).toBe(200);
    expect(pointsAfterExtraTaskRes.body.value[child.id] || 0).toBe(pointsAfterApprove + 7);

    const bonusRes = await request(app)
      .post('/api/point-adjustments')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        type: 'BONUS',
        points: 5,
        note: 'Premia za samodzielność',
      });
    expect(bonusRes.status).toBe(201);
    expect(bonusRes.body.pointAdjustment.delta).toBe(5);

    const penaltyRes = await request(app)
      .post('/api/point-adjustments')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        type: 'PENALTY',
        points: 3,
        note: 'Kara za bałagan',
      });
    expect(penaltyRes.status).toBe(201);
    expect(penaltyRes.body.pointAdjustment.delta).toBe(-3);

    const childPointAdjustmentsRes = await request(app)
      .get('/api/storage/get/pointAdjustments')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childPointAdjustmentsRes.status).toBe(200);
    expect(childPointAdjustmentsRes.body.value).toHaveLength(2);

    const pointsAfterAdjustmentRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsAfterAdjustmentRes.status).toBe(200);
    expect(pointsAfterAdjustmentRes.body.value[child.id] || 0).toBe(pointsAfterApprove + 9);

    const stalePointsAfterPenaltyRes = await request(app)
      .post('/api/storage/merge')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        values: {
          points: { [child.id]: pointsAfterApprove + 12 },
        },
      });
    expect(stalePointsAfterPenaltyRes.status).toBe(200);

    const pointsAfterStaleMergeRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsAfterStaleMergeRes.status).toBe(200);
    expect(pointsAfterStaleMergeRes.body.value[child.id] || 0).toBe(pointsAfterApprove + 9);

    const completionsRes = await request(app)
      .get(`/api/completions?childId=${encodeURIComponent(child.id)}&date=${today}`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(completionsRes.status).toBe(200);
    expect(
      (completionsRes.body.completions || []).some((item) => item.approvedByParent === true),
    ).toBe(true);

    const forgotRes = await request(app).post('/api/auth/forgot-password').send({
      email: parentPayload.email,
    });
    expect(forgotRes.status).toBe(200);
    expect(forgotRes.body.debugResetToken).toBeTruthy();

    const newPassword = TEST_RESET_PASSWORD;
    const resetRes = await request(app).post('/api/auth/reset-password/token').send({
      token: forgotRes.body.debugResetToken,
      newPassword,
    });
    expect(resetRes.status).toBe(200);

    const loginAfterResetRes = await request(app).post('/api/auth/login').send({
      email: parentPayload.email,
      password: newPassword,
    });
    expect(loginAfterResetRes.status).toBe(200);
    expect(loginAfterResetRes.body.token).toBeTruthy();
    expect(loginAfterResetRes.body.user).not.toHaveProperty('pinCode');
  });

  test('child access codes are globally unique and protected from storage snapshots', async () => {
    const suffix = `global-code-${Date.now()}`;
    const firstParentPayload = createParentPayload(`${suffix}-first`);
    const firstRegisterRes = await request(app).post('/api/auth/register').send(firstParentPayload);
    expect(firstRegisterRes.status).toBe(201);
    expect(firstRegisterRes.body.user).not.toHaveProperty('pinCode');
    const firstParentToken = firstRegisterRes.body.token;

    const firstMeRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${firstParentToken}`);
    expect(firstMeRes.status).toBe(200);
    expect(firstMeRes.body.user).not.toHaveProperty('pinCode');

    const firstChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${firstParentToken}`)
      .send({
        name: `Pierwsze-${suffix}`,
        avatar: '🦊',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(firstChildRes.status).toBe(201);
    const takenCode = firstChildRes.body.child.accessCode;
    expect(takenCode).toMatch(/^\d{4}$/);

    const secondParentToken = await registerParent(`${suffix}-second`);

    const conflictingCreateRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${secondParentToken}`)
      .send({
        name: `Konflikt-${suffix}`,
        avatar: '🐼',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
        accessCode: takenCode,
      });
    expect(conflictingCreateRes.status).toBe(409);

    const secondChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${secondParentToken}`)
      .send({
        name: `Drugie-${suffix}`,
        avatar: '🐸',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(secondChildRes.status).toBe(201);
    const secondChild = secondChildRes.body.child;
    expect(secondChild.accessCode).toMatch(/^\d{4}$/);
    expect(secondChild.accessCode).not.toBe(takenCode);
    const secondChildLoginCode = secondChild.accessCode;

    const conflictingUpdateRes = await request(app)
      .put(`/api/children/${secondChild.id}`)
      .set('Authorization', `Bearer ${secondParentToken}`)
      .send({ accessCode: takenCode });
    expect(conflictingUpdateRes.status).toBe(409);

    const snapshotMergeRes = await request(app)
      .post('/api/storage/merge')
      .set('Authorization', `Bearer ${secondParentToken}`)
      .send({
        values: {
          children: [
            {
              ...secondChild,
              name: 'Nadpisane snapshotem',
              accessCode: takenCode,
              updatedAt: new Date().toISOString(),
            },
            {
              id: `fake-child-${suffix}`,
              name: 'Nie powinno powstac',
              avatar: '🐱',
              activeDays: [1],
              accessCode: '9999',
              archived: false,
            },
          ],
        },
      });
    expect(snapshotMergeRes.status).toBe(200);

    const secondChildrenAfterSnapshotRes = await request(app)
      .get('/api/children')
      .set('Authorization', `Bearer ${secondParentToken}`);
    expect(secondChildrenAfterSnapshotRes.status).toBe(200);
    expect(secondChildrenAfterSnapshotRes.body.children).toHaveLength(1);
    expect(secondChildrenAfterSnapshotRes.body.children[0].name).toBe(secondChild.name);
    expect(secondChildrenAfterSnapshotRes.body.children[0]).not.toHaveProperty('accessCode');
    const secondChildLoginAfterSnapshotRes = await request(app)
      .post('/api/auth/login-child')
      .send({ accessCode: secondChildLoginCode });
    expect(secondChildLoginAfterSnapshotRes.status).toBe(200);

    const restoreRes = await request(app)
      .post('/api/storage/restore-backup')
      .set('Authorization', `Bearer ${secondParentToken}`)
      .send({
        backup: makeBackupState({
          children: [
            {
              id: `restore-a-${suffix}`,
              name: 'Restore A',
              avatar: '🦁',
              activeDays: [1, 2, 3, 4, 5, 6, 7],
              accessCode: takenCode,
              archived: false,
            },
            {
              id: `restore-b-${suffix}`,
              name: 'Restore B',
              avatar: '🐯',
              activeDays: [1, 2, 3, 4, 5, 6, 7],
              accessCode: secondChildLoginCode,
              archived: false,
            },
          ],
        }),
      });
    expect(restoreRes.status).toBe(200);
    expect(restoreRes.body.childAccessCodes).toHaveLength(2);

    const restoredChildrenRes = await request(app)
      .get('/api/children')
      .set('Authorization', `Bearer ${secondParentToken}`);
    expect(restoredChildrenRes.status).toBe(200);
    const restoredCodes = restoreRes.body.childAccessCodes.map((item) => item.accessCode);
    expect(restoredChildrenRes.body.children).toHaveLength(2);
    expect(restoredChildrenRes.body.children.some((child) => Object.prototype.hasOwnProperty.call(child, 'accessCode'))).toBe(false);
    expect(restoredCodes).not.toContain(takenCode);
    expect(new Set(restoredCodes).size).toBe(restoredCodes.length);
    for (const accessCode of restoredCodes) {
      const restoredChildLoginRes = await request(app)
        .post('/api/auth/login-child')
        .send({ accessCode });
      expect(restoredChildLoginRes.status).toBe(200);
    }
  });

  test('child login blocks repeated guesses for the same code across IPs', async () => {
    let guessedCode = null;
    for (let i = 9000; i < 10000; i += 1) {
      const candidate = String(i);
      const codeLookupHash = crypto
        .createHmac('sha256', process.env.CHILD_CODE_PEPPER)
        .update(candidate, 'utf8')
        .digest('hex');
      const existing = await prisma.childAccessCredential.findUnique({ where: { codeLookupHash } });
      if (!existing) {
        guessedCode = candidate;
        break;
      }
    }
    expect(guessedCode).toMatch(/^\d{4}$/);
    for (let i = 0; i < 8; i += 1) {
      const failedRes = await request(app)
        .post('/api/auth/login-child')
        .set('X-Forwarded-For', `198.51.100.${i + 1}`)
        .send({ accessCode: guessedCode });
      expect(failedRes.status).toBe(401);
    }

    const blockedRes = await request(app)
      .post('/api/auth/login-child')
      .set('X-Forwarded-For', '198.51.100.99')
      .send({ accessCode: guessedCode });
    expect(blockedRes.status).toBe(429);
  });

  test('streak and passed-day points require all MIN tasks approved for the day', async () => {
    const suffix = `all-min-${Date.now()}`;
    const today = getToday();
    const registerRes = await request(app).post('/api/auth/register').send(createParentPayload(suffix));
    expect(registerRes.status).toBe(201);
    const parentToken = registerRes.body.token;

    const addChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        name: `Miny-${suffix}`,
        avatar: '⭐',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(addChildRes.status).toBe(201);
    const child = addChildRes.body.child;

    const createMinTask = async (title) => {
      const response = await request(app)
        .post('/api/tasks')
        .set('Authorization', `Bearer ${parentToken}`)
        .send({
          childId: child.id,
          title,
          tier: 'MIN',
          points: 0,
        });
      expect(response.status).toBe(201);
      return response.body.task;
    };

    const firstTask = await createMinTask('Pierwsze minimum');
    const secondTask = await createMinTask('Drugie minimum');

    const completeAndApprove = async (task) => {
      const completionRes = await request(app)
        .post('/api/completions')
        .set('Authorization', `Bearer ${parentToken}`)
        .send({
          taskId: task.id,
          childId: child.id,
          date: today,
          doneByChild: true,
        });
      expect(completionRes.status).toBe(201);

      const approveRes = await request(app)
        .post(`/api/completions/${completionRes.body.completion.id}/approve`)
        .set('Authorization', `Bearer ${parentToken}`);
      expect(approveRes.status).toBe(200);
    };

    await completeAndApprove(firstTask);

    const partialPointsRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(partialPointsRes.status).toBe(200);
    expect(partialPointsRes.body.value[child.id] || 0).toBe(0);

    const partialStreaksRes = await request(app)
      .get('/api/storage/get/streaks')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(partialStreaksRes.status).toBe(200);
    expect(partialStreaksRes.body.value[child.id].current).toBe(0);

    await completeAndApprove(secondTask);

    const completePointsRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(completePointsRes.status).toBe(200);
    expect(completePointsRes.body.value[child.id] || 0).toBeGreaterThanOrEqual(2);

    const completeStreaksRes = await request(app)
      .get('/api/storage/get/streaks')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(completeStreaksRes.status).toBe(200);
    expect(completeStreaksRes.body.value[child.id].current).toBe(1);
    expect(completeStreaksRes.body.value[child.id].best).toBe(1);
  });

  test('point adjustment retries once after a transient family state conflict', async () => {
    const suffix = `points-retry-${Date.now()}`;
    const registerRes = await request(app).post('/api/auth/register').send(createParentPayload(suffix));
    expect(registerRes.status).toBe(201);
    const parentToken = registerRes.body.token;

    const addChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        name: `Retry-${suffix}`,
        avatar: '⭐',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(addChildRes.status).toBe(201);
    const child = addChildRes.body.child;

    const bonusRes = await request(app)
      .post('/api/point-adjustments')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        type: 'BONUS',
        points: 5,
        note: 'Punkty startowe',
      });
    expect(bonusRes.status).toBe(201);

    const originalTransaction = prisma.$transaction.bind(prisma);
    let injectedConflict = false;
    const transactionSpy = jest.spyOn(prisma, '$transaction').mockImplementation(async (...args) => {
      if (!injectedConflict) {
        injectedConflict = true;
        const conflict = new Error('could not serialize access due to concurrent update');
        conflict.code = 'P2034';
        throw conflict;
      }
      return originalTransaction(...args);
    });

    try {
      const penaltyRes = await request(app)
        .post('/api/point-adjustments')
        .set('Authorization', `Bearer ${parentToken}`)
        .send({
          childId: child.id,
          type: 'PENALTY',
          points: 2,
          note: 'Retry konfliktu',
        });
      expect(penaltyRes.status).toBe(201);
      expect(injectedConflict).toBe(true);
      expect(penaltyRes.body.pointAdjustment.delta).toBe(-2);
      expect(penaltyRes.body.points[child.id]).toBe(3);
    } finally {
      transactionSpy.mockRestore();
    }

    const adjustmentsRes = await request(app)
      .get('/api/storage/get/pointAdjustments')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(adjustmentsRes.status).toBe(200);
    expect(adjustmentsRes.body.value.filter((adjustment) => adjustment.note === 'Retry konfliktu')).toHaveLength(1);

    const pointsRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsRes.status).toBe(200);
    expect(pointsRes.body.value[child.id]).toBe(3);

    const snapshotBeforeConflict = await request(app)
      .get('/api/family-state')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(snapshotBeforeConflict.status).toBe(200);
    const permanentConflict = new Error('family state version changed');
    permanentConflict.code = 'FAMILY_STATE_VERSION_CONFLICT';
    const conflictSpy = jest.spyOn(prisma, '$transaction').mockRejectedValueOnce(permanentConflict);
    try {
      const rejectedRes = await request(app)
        .post('/api/point-adjustments')
        .set('Authorization', `Bearer ${parentToken}`)
        .send({
          childId: child.id,
          type: 'BONUS',
          points: 1,
          note: 'Nie zostanie zapisane',
        });
      expect(rejectedRes.status).toBe(409);
      expect(rejectedRes.body.code).toBe('FAMILY_STATE_VERSION_CONFLICT');
      expect(rejectedRes.body.currentVersion).toBe(snapshotBeforeConflict.body.version);
    } finally {
      conflictSpy.mockRestore();
    }
  });

  test('completion and extra task APIs enforce schedule and date policy', async () => {
    const suffix = `schedule-dates-${Date.now()}`;
    const parentToken = await registerParent(suffix);
    const child = {
      id: `child-schedule-${suffix}`,
      name: 'Harmonogram',
      avatar: '⭐',
      activeDays: [1, 2, 3, 4, 5],
      accessCode: '1201',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    const mondayTask = {
      id: `task-monday-${suffix}`,
      childId: child.id,
      title: 'Tylko poniedziałek',
      tier: 'MIN',
      points: 3,
      daysOfWeek: [1],
      active: true,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    const sundayTask = {
      id: `task-sunday-${suffix}`,
      childId: child.id,
      title: 'Tylko niedziela',
      tier: 'MIN',
      points: 3,
      daysOfWeek: [7],
      active: true,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    await restoreFamilyState(parentToken, { children: [child], tasks: [mondayTask, sundayTask] });

    const validCompletionRes = await request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        taskId: mondayTask.id,
        childId: child.id,
        date: '2026-05-11',
        doneByChild: true,
      });
    expect(validCompletionRes.status).toBe(201);

    const wrongScheduleRes = await request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        taskId: mondayTask.id,
        childId: child.id,
        date: '2026-05-12',
        doneByChild: true,
      });
    expect(wrongScheduleRes.status).toBe(400);
    expect(wrongScheduleRes.body.error).toMatch(/zaplanowane/);

    const inactiveDayRes = await request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        taskId: sundayTask.id,
        childId: child.id,
        date: '2026-05-17',
        doneByChild: true,
      });
    expect(inactiveDayRes.status).toBe(400);
    expect(inactiveDayRes.body.error).toMatch(/aktywnego dnia/);

    const futureCompletionRes = await request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        taskId: mondayTask.id,
        childId: child.id,
        date: '2999-01-05',
        doneByChild: true,
      });
    expect(futureCompletionRes.status).toBe(400);
    expect(futureCompletionRes.body.error).toMatch(/przyszłości/);

    const futureExtraTaskRes = await request(app)
      .post('/api/extra-tasks')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        title: 'Zadanie z przyszłości',
        date: '2999-01-05',
      });
    expect(futureExtraTaskRes.status).toBe(400);
    expect(futureExtraTaskRes.body.error).toMatch(/przyszłości/);
  });

  test('WEEKLY tasks grant task points once per week', async () => {
    const suffix = `weekly-${Date.now()}`;
    const parentToken = await registerParent(suffix);
    const child = {
      id: `child-weekly-${suffix}`,
      name: 'Tygodniowy',
      avatar: '⭐',
      activeDays: [1, 2, 3, 4, 5, 6, 7],
      accessCode: '1202',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    const weeklyTask = {
      id: `task-weekly-${suffix}`,
      childId: child.id,
      title: 'Trening tygodniowy',
      tier: 'WEEKLY',
      points: 10,
      daysOfWeek: [1, 3],
      active: true,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    const restoredWeeklyState = await restoreFamilyState(parentToken, { children: [child], tasks: [weeklyTask] });
    const restoredWeeklyCode = restoredWeeklyState.childAccessCodes.find((item) => item.childId === child.id)?.accessCode;
    expect(restoredWeeklyCode).toMatch(/^\d{4}$/);

    const completeAndApprove = async (date) => {
      const completionRes = await request(app)
        .post('/api/completions')
        .set('Authorization', `Bearer ${parentToken}`)
        .send({
          taskId: weeklyTask.id,
          childId: child.id,
          date,
          doneByChild: true,
        });
      expect(completionRes.status).toBe(201);
      const approveRes = await request(app)
        .post(`/api/completions/${completionRes.body.completion.id}/approve`)
        .set('Authorization', `Bearer ${parentToken}`);
      expect(approveRes.status).toBe(200);
    };

    await completeAndApprove('2026-05-11');
    await completeAndApprove('2026-05-13');

    const pointsRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsRes.status).toBe(200);
    expect(pointsRes.body.value[child.id]).toBe(10);

    const taskPointGrantsRes = await request(app)
      .get('/api/storage/get/taskPointGrants')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(taskPointGrantsRes.status).toBe(200);
    expect(Object.keys(taskPointGrantsRes.body.value).filter((key) => key.includes(weeklyTask.id))).toHaveLength(1);

    const pointLedgerRes = await request(app)
      .get('/api/storage/get/pointLedger')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointLedgerRes.status).toBe(200);
    expect(
      pointLedgerRes.body.value.filter((entry) => entry.sourceType === 'COMPLETION' && entry.sourceId),
    ).toHaveLength(1);

    const bonusRes = await request(app)
      .post('/api/point-adjustments')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId: child.id,
        type: 'BONUS',
        points: 1,
        note: 'Drugi wpis do paginacji',
      });
    expect(bonusRes.status).toBe(201);

    const ledgerPageOneRes = await request(app)
      .get(`/api/point-ledger?childId=${encodeURIComponent(child.id)}&limit=1&cursor=0`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(ledgerPageOneRes.status).toBe(200);
    expect(ledgerPageOneRes.body.entries).toHaveLength(1);
    expect(ledgerPageOneRes.body.nextCursor).toBe(1);
    expect(ledgerPageOneRes.body.total).toBeGreaterThan(1);

    const ledgerPageTwoRes = await request(app)
      .get(`/api/point-ledger?childId=${encodeURIComponent(child.id)}&limit=1&cursor=1`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(ledgerPageTwoRes.status).toBe(200);
    expect(ledgerPageTwoRes.body.entries).toHaveLength(1);
    expect(ledgerPageTwoRes.body.entries[0].id).not.toBe(ledgerPageOneRes.body.entries[0].id);

    const childrenRes = await request(app)
      .get('/api/storage/get/children')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(childrenRes.status).toBe(200);
    const currentChild = childrenRes.body.value.find((item) => item.id === child.id);
    expect(currentChild).toBeTruthy();
    expect(currentChild).not.toHaveProperty('accessCode');

    const childLoginRes = await request(app).post('/api/auth/login-child').send({
      accessCode: restoredWeeklyCode,
    });
    expect(childLoginRes.status).toBe(200);
    const childLedgerRes = await request(app)
      .get('/api/point-ledger?limit=2')
      .set('Authorization', `Bearer ${childLoginRes.body.token}`);
    expect(childLedgerRes.status).toBe(200);
    expect(childLedgerRes.body.childId).toBe(child.id);
    expect(childLedgerRes.body.entries.every((entry) => entry.childId === child.id)).toBe(true);
  });

  test('active days without MIN tasks do not count as passed days', async () => {
    const suffix = `no-required-${Date.now()}`;
    const parentToken = await registerParent(suffix);
    const child = {
      id: `child-no-required-${suffix}`,
      name: 'Bez minimum',
      avatar: '⭐',
      activeDays: [1, 2, 3, 4, 5, 6, 7],
      accessCode: '1203',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    const plusTask = {
      id: `task-plus-${suffix}`,
      childId: child.id,
      title: 'Bonus bez minimum',
      tier: 'PLUS',
      points: 0,
      daysOfWeek: [1],
      active: true,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    };
    await restoreFamilyState(parentToken, { children: [child], tasks: [plusTask] });

    const completionRes = await request(app)
      .post('/api/completions')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        taskId: plusTask.id,
        childId: child.id,
        date: '2026-05-11',
        doneByChild: true,
      });
    expect(completionRes.status).toBe(201);

    const approveRes = await request(app)
      .post(`/api/completions/${completionRes.body.completion.id}/approve`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(approveRes.status).toBe(200);

    const pointsRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsRes.status).toBe(200);
    expect(pointsRes.body.value[child.id] || 0).toBe(0);

    const streaksRes = await request(app)
      .get('/api/storage/get/streaks')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(streaksRes.status).toBe(200);
    expect(streaksRes.body.value[child.id].current).toBe(0);

    const dayPointGrantsRes = await request(app)
      .get('/api/storage/get/dayPointGrants')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(dayPointGrantsRes.status).toBe(200);
    expect(Object.keys(dayPointGrantsRes.body.value)).toHaveLength(0);
  });

  test('point rewards unlock once per completed points threshold and restore the affected cycle', async () => {
    const suffix = `reward-threshold-${Date.now()}`;
    const parentToken = await registerParent(suffix);
    const addChildRes = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        name: `Nagrody-${suffix}`,
        avatar: '⭐',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
      });
    expect(addChildRes.status).toBe(201);
    const child = addChildRes.body.child;

    const rewardRes = await request(app)
      .post('/api/rewards')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        title: 'Nagroda za 5 punktów',
        requiredPoints: 5,
      });
    expect(rewardRes.status).toBe(201);
    const reward = rewardRes.body.reward;

    const grantBonus = async (points, note) => {
      const response = await request(app)
        .post('/api/point-adjustments')
        .set('Authorization', `Bearer ${parentToken}`)
        .send({
          childId: child.id,
          type: 'BONUS',
          points,
          note,
        });
      expect(response.status).toBe(201);
      return response;
    };

    const applyPenalty = async (points, note) => {
      const response = await request(app)
        .post('/api/point-adjustments')
        .set('Authorization', `Bearer ${parentToken}`)
        .send({
          childId: child.id,
          type: 'PENALTY',
          points,
          note,
        });
      expect(response.status).toBe(201);
      return response;
    };

    await grantBonus(5, 'Próg nagrody');

    const unlockedRewardsRes = await request(app)
      .get('/api/rewards')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(unlockedRewardsRes.status).toBe(200);
    const firstUnlock = unlockedRewardsRes.body.rewardUnlocks.find(
      (unlock) => unlock.childId === child.id && unlock.rewardId === reward.id,
    );
    expect(firstUnlock).toBeTruthy();
    expect(firstUnlock.cycle).toBe(1);

    await grantBonus(5, 'Drugi próg nagrody');

    const repeatedRewardsRes = await request(app)
      .get('/api/rewards')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(repeatedRewardsRes.status).toBe(200);
    const repeatedUnlocks = repeatedRewardsRes.body.rewardUnlocks
      .filter((unlock) => unlock.childId === child.id && unlock.rewardId === reward.id)
      .sort((left, right) => left.cycle - right.cycle);
    expect(repeatedUnlocks).toHaveLength(2);
    expect(repeatedUnlocks.map((unlock) => unlock.cycle)).toEqual([1, 2]);
    const secondUnlock = repeatedUnlocks[1];

    const rewardHistoryRes = await request(app)
      .get('/api/rewards/history')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(rewardHistoryRes.status).toBe(200);
    expect(rewardHistoryRes.body.rewardUnlockHistory.find((entry) => entry.id === secondUnlock.id)).toMatchObject({
      cycle: 2,
      thresholdPoints: 10,
    });

    await applyPenalty(2, 'Spadek poniżej drugiego progu');

    const revokedRewardsRes = await request(app)
      .get('/api/rewards')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(revokedRewardsRes.status).toBe(200);
    const activeUnlocksAfterPenalty = revokedRewardsRes.body.rewardUnlocks
      .filter((unlock) => unlock.childId === child.id && unlock.rewardId === reward.id)
      .sort((left, right) => left.cycle - right.cycle);
    expect(activeUnlocksAfterPenalty).toHaveLength(1);
    expect(activeUnlocksAfterPenalty[0].id).toBe(firstUnlock.id);
    expect(activeUnlocksAfterPenalty[0].cycle).toBe(1);

    const childUnlocksAfterPenaltyRes = await request(app)
      .get('/api/storage/get/rewardUnlocks')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(childUnlocksAfterPenaltyRes.status).toBe(200);
    expect(
      childUnlocksAfterPenaltyRes.body.value.some((unlock) => unlock.id === secondUnlock.id),
    ).toBe(false);

    await grantBonus(2, 'Powrót do drugiego progu');

    const restoredRewardsRes = await request(app)
      .get('/api/rewards')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(restoredRewardsRes.status).toBe(200);
    const restoredUnlock = restoredRewardsRes.body.rewardUnlocks.find((unlock) => unlock.id === secondUnlock.id);
    expect(restoredUnlock).toBeTruthy();
    expect(restoredUnlock.cycle).toBe(2);
    expect(restoredUnlock.restoredAt).toBeTruthy();
  });

  test('legacy point reward unlock is retained as cycle one and backfilled for every earned threshold', () => {
    const data = makeBackupState({
      children: [{ id: 'child-ignacy', name: 'Ignacy', avatar: '⭐', activeDays: [1, 2, 3, 4, 5, 6, 7] }],
      rewards: [{ id: 'reward-30', title: '30 zł', requiredPoints: 50, active: true }],
      points: { 'child-ignacy': 137 },
      rewardUnlocks: [{
        id: 'legacy-unlock',
        childId: 'child-ignacy',
        rewardId: 'reward-30',
        unlockedAt: '2026-05-14T10:00:00.000Z',
        claimedAt: null,
        revokedAt: null,
      }],
    });

    expect(__test.reconcileRewardUnlocksForAllChildren(data, null, '2026-07-11T12:00:00.000Z')).toBe(true);
    const unlocks = data.rewardUnlocks
      .filter((unlock) => unlock.childId === 'child-ignacy' && unlock.rewardId === 'reward-30')
      .sort((left, right) => left.cycle - right.cycle);
    expect(unlocks).toHaveLength(2);
    expect(unlocks.map((unlock) => unlock.cycle)).toEqual([1, 2]);
    expect(unlocks[0].id).toBe('legacy-unlock');

    data.points['child-ignacy'] = 75;
    expect(__test.reconcileRewardUnlocksForAllChildren(data, null, '2026-07-11T12:01:00.000Z')).toBe(true);
    expect(unlocks[0].revokedAt).toBeNull();
    expect(unlocks[1].revokedAt).toBeTruthy();

    data.points['child-ignacy'] = 137;
    expect(__test.reconcileRewardUnlocksForAllChildren(data, null, '2026-07-11T12:02:00.000Z')).toBe(true);
    expect(unlocks[1].revokedAt).toBeNull();
    expect(unlocks[1].restoredAt).toBeTruthy();
  });
});

test('same-day task archiving keeps an already approved completion, points and passed day', () => {
  const data = makeBackupState({
    children: [{ id: 'child-a', name: 'A', avatar: '⭐', activeDays: [1, 2, 3, 4, 5, 6, 7], createdAt: '2026-01-01T08:00:00.000Z' }],
    tasks: [{ id: 'task-a', childId: 'child-a', title: 'Minimum', tier: 'MIN', points: 2, daysOfWeek: [], active: true, createdAt: '2026-01-01T08:00:00.000Z' }],
    completions: [{ id: 'completion-a', childId: 'child-a', taskId: 'task-a', date: '2026-01-05', doneByChild: true, approvedByParent: true, approvedAt: '2026-01-05T09:00:00.000Z' }],
  });

  __test.recomputePointsAndGrants(data);
  expect(data.points['child-a']).toBe(4);

  data.tasks[0] = {
    ...data.tasks[0],
    active: false,
    archivedAt: '2026-01-05T18:00:00.000Z',
    updatedAt: '2026-01-05T18:00:00.000Z',
  };
  __test.recomputePointsAndGrants(data);

  expect(data.points['child-a']).toBeGreaterThanOrEqual(4);
  expect(data.pointLedger.some((entry) => entry.type === 'TASK_APPROVED' && entry.delta === 2)).toBe(true);
  expect(data.pointLedger.some((entry) => entry.type === 'DAY_PASSED')).toBe(true);
});

maybeDescribe('Task history invariants', () => {
  afterAll(async () => {
    await prisma.$disconnect();
  });

  test('does not rewrite approved history after task rule changes and keeps same-day archive points', async () => {
    const suffix = `history-${Date.now()}`;
    const parentToken = await registerParent(suffix);
    const childId = `history-child-${suffix}`;
    const taskId = `history-task-${suffix}`;
    const today = getToday();
    const approvedAt = new Date(Date.now() - 60 * 1000).toISOString();

    await restoreFamilyState(parentToken, {
      children: [{
        id: childId,
        name: 'Historia',
        avatar: '⭐',
        activeDays: [1, 2, 3, 4, 5, 6, 7],
        createdAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      }],
      tasks: [{
        id: taskId,
        childId,
        title: 'Stare minimum',
        tier: 'MIN',
        points: 2,
        daysOfWeek: [],
        active: true,
        createdAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      }],
      completions: [{
        id: `history-completion-${suffix}`,
        taskId,
        childId,
        date: today,
        doneByChild: true,
        approvedByParent: true,
        approvedAt,
        createdAt: approvedAt,
        updatedAt: approvedAt,
      }],
    });

    const editRes = await request(app)
      .put(`/api/tasks/${taskId}`)
      .set('Authorization', `Bearer ${parentToken}`)
      .send({ points: 50 });
    expect(editRes.status).toBe(409);

    const archiveRes = await request(app)
      .delete(`/api/tasks/${taskId}`)
      .set('Authorization', `Bearer ${parentToken}`);
    expect(archiveRes.status).toBe(200);

    const pointsRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsRes.status).toBe(200);
    expect(pointsRes.body.value[childId]).toBeGreaterThanOrEqual(4);
  });
});
