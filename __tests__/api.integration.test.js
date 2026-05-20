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
};

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
    expect(registerRes.body.user).not.toHaveProperty('pinCode');

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
    expect(secondChildrenAfterSnapshotRes.body.children[0].accessCode).toBe(secondChild.accessCode);

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
              accessCode: secondChild.accessCode,
              archived: false,
            },
          ],
        }),
      });
    expect(restoreRes.status).toBe(200);

    const restoredChildrenRes = await request(app)
      .get('/api/children')
      .set('Authorization', `Bearer ${secondParentToken}`);
    expect(restoredChildrenRes.status).toBe(200);
    const restoredCodes = restoredChildrenRes.body.children.map((child) => child.accessCode);
    expect(restoredChildrenRes.body.children).toHaveLength(2);
    expect(restoredCodes).not.toContain(takenCode);
    expect(new Set(restoredCodes).size).toBe(restoredCodes.length);
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

    const originalUpdateMany = prisma.familyState.updateMany.bind(prisma.familyState);
    let injectedConflict = false;
    const updateManySpy = jest.spyOn(prisma.familyState, 'updateMany').mockImplementation(async (args) => {
      const statePayload = args?.data?.data;
      const hasRetryPenalty =
        Array.isArray(statePayload?.pointAdjustments) &&
        statePayload.pointAdjustments.some((adjustment) => adjustment.note === 'Retry konfliktu');
      if (!injectedConflict && hasRetryPenalty) {
        injectedConflict = true;
        return { count: 0 };
      }
      return originalUpdateMany(args);
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
      updateManySpy.mockRestore();
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
    await restoreFamilyState(parentToken, { children: [child], tasks: [weeklyTask] });

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

  test('point rewards are revoked after point loss and restored after points are regained', async () => {
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

    await applyPenalty(2, 'Spadek poniżej progu');

    const revokedRewardsRes = await request(app)
      .get('/api/rewards')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(revokedRewardsRes.status).toBe(200);
    expect(
      revokedRewardsRes.body.rewardUnlocks.some((unlock) => unlock.childId === child.id && unlock.rewardId === reward.id),
    ).toBe(false);

    const childUnlocksAfterPenaltyRes = await request(app)
      .get('/api/storage/get/rewardUnlocks')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(childUnlocksAfterPenaltyRes.status).toBe(200);
    expect(
      childUnlocksAfterPenaltyRes.body.value.some((unlock) => unlock.childId === child.id && unlock.rewardId === reward.id),
    ).toBe(false);

    await grantBonus(2, 'Powrót do progu');

    const restoredRewardsRes = await request(app)
      .get('/api/rewards')
      .set('Authorization', `Bearer ${parentToken}`);
    expect(restoredRewardsRes.status).toBe(200);
    const restoredUnlock = restoredRewardsRes.body.rewardUnlocks.find(
      (unlock) => unlock.childId === child.id && unlock.rewardId === reward.id,
    );
    expect(restoredUnlock).toBeTruthy();
    expect(restoredUnlock.id).toBe(firstUnlock.id);
    expect(restoredUnlock.restoredAt).toBeTruthy();
  });
});
