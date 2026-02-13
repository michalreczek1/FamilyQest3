require('dotenv').config();

const request = require('supertest');
const { app, prisma } = require('../server');

const hasDatabase = Boolean(process.env.DATABASE_URL);

const maybeDescribe = hasDatabase ? describe : describe.skip;

const createParentPayload = (suffix) => ({
  email: `jest.parent.${suffix}@familyquest.local`,
  password: 'JestHaslo123!',
  pinCode: '2468',
  familyName: 'Jest Rodzina',
});

const getToday = () => new Date().toISOString().slice(0, 10);

maybeDescribe('FamilyQuest API integration', () => {
  jest.setTimeout(60000);

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

    const parentToken = registerRes.body.token;

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

    const childToken = childLoginRes.body.token;

    const childForbiddenRes = await request(app)
      .get('/api/auth/parents')
      .set('Authorization', `Bearer ${childToken}`);
    expect(childForbiddenRes.status).toBe(403);

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

    const newPassword = 'JestNoweHaslo999!';
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
  });
});
