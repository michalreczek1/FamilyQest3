require('dotenv').config();
process.env.ALLOW_DEBUG_RESET_TOKEN = 'true';

const request = require('supertest');
const { app, prisma } = require('../server');

const hasDatabase = Boolean(process.env.DATABASE_URL);

const maybeDescribe = hasDatabase ? describe : describe.skip;
const TEST_PARENT_PASSWORD = 'TestParentPass123!';
const TEST_RESET_PASSWORD = 'TestResetPass999!';

const createParentPayload = (suffix) => ({
  email: `jest.parent.${suffix}@familyquest.local`,
  password: TEST_PARENT_PASSWORD,
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
    expect(duplicateApproveRes.status).toBe(200);

    const pointsAfterDuplicateApproveRes = await request(app)
      .get('/api/storage/get/points')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(pointsAfterDuplicateApproveRes.status).toBe(200);
    expect(pointsAfterDuplicateApproveRes.body.value[child.id] || 0).toBe(pointsAfterApprove);

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
    expect(completePointsRes.body.value[child.id] || 0).toBe(2);

    const completeStreaksRes = await request(app)
      .get('/api/storage/get/streaks')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(completeStreaksRes.status).toBe(200);
    expect(completeStreaksRes.body.value[child.id].current).toBe(1);
    expect(completeStreaksRes.body.value[child.id].best).toBe(1);
  });
});
