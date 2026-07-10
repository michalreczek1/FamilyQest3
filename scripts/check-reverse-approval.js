const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');
require('./test-env');
const { __test, prisma } = require('../server');

const rootDir = path.join(__dirname, '..', 'dist');
let staticServer = null;

const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

const startStaticServer = () =>
  new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const rawPath = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
      const filePath = path.normalize(path.join(rootDir, rawPath));
      if (!filePath.startsWith(rootDir)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }
      fs.readFile(filePath, (error, content) => {
        if (error) {
          res.writeHead(404);
          res.end('Not found');
          return;
        }
        res.writeHead(200, {
          'Content-Type': contentTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
          'Cache-Control': 'no-store',
        });
        res.end(content);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      staticServer = server;
      resolve(`http://127.0.0.1:${port}`);
    });
  });

const today = new Date().toISOString().slice(0, 10);
const child = {
  id: 'child-reverse',
  name: 'Ignacy',
  avatar: '👦',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '1234',
  createdAt: '2026-01-01T00:00:00.000Z',
};
const tasks = [
  {
    id: 'task-min-1',
    childId: child.id,
    title: 'Poranne zadanie',
    tier: 'MIN',
    points: 3,
    daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
    active: true,
    createdAt: '2026-01-01T00:00:00.000Z',
  },
  {
    id: 'task-min-2',
    childId: child.id,
    title: 'Drugie zadanie',
    tier: 'MIN',
    points: 4,
    daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
    active: true,
    createdAt: '2026-01-01T00:00:00.000Z',
  },
];

const makeState = (date = today) => ({
  children: [child],
  tasks,
  completions: tasks.map((task, index) => ({
    id: `comp-${index + 1}`,
    taskId: task.id,
    childId: child.id,
    date,
    doneByChild: true,
    doneAt: `${date}T08:0${index}:00.000Z`,
    approvedByParent: true,
    approvedAt: `${date}T09:0${index}:00.000Z`,
    rejectedByParent: false,
    rejectedAt: null,
    createdAt: `${date}T08:0${index}:00.000Z`,
    updatedAt: `${date}T09:0${index}:00.000Z`,
  })),
  extraTasks: [],
  pointAdjustments: [],
  rewards: [],
  streaks: {},
  points: {},
  rewardUnlocks: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
});

const runLogicCheck = () => {
  const state = makeState('2026-05-13');
  __test.recomputePointsAndGrants(state);
  assert.strictEqual(state.points[child.id], 9, 'initial points should include task points and passed-day points');

  const result = __test.reverseApprovalEffects(
    state,
    state.completions.find((item) => item.id === 'comp-1'),
    'parent-test',
    'Test reversal',
    '2026-05-13T10:00:00.000Z',
  );

  assert(result, 'reverse approval should return a result');
  assert.strictEqual(result.reversal.previousPoints, 9);
  assert.strictEqual(result.reversal.newPoints, 4);
  assert.strictEqual(result.reversal.delta, -5);
  assert.strictEqual(result.completion.approvedByParent, false);
  assert.strictEqual(result.completion.rejectedByParent, true);
  assert.strictEqual(result.pointAdjustment.type, 'REVERSAL');
  assert.strictEqual(result.pointAdjustment.affectsBalance, false);

  __test.recomputePointsAndGrants(state);
  assert.strictEqual(state.points[child.id], 4, 'recompute must not apply reversal adjustment twice');
};

const runUiCheck = async () => {
  const baseUrl = process.env.REVERSE_APPROVAL_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1366, height: 760 } });
  const storageValues = makeState(today);
  storageValues.points = { [child.id]: 9 };
  storageValues.streaks = { [child.id]: { current: 1, best: 1, idealWeeksCount: 0, idealWeeksInRow: 0 } };

  const dialogMessages = [];
  page.on('dialog', async (dialog) => {
    dialogMessages.push(dialog.message());
    await dialog.accept();
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/family-state') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          familyId: 'family-test', version: 1, generatedAt: `${today}T09:00:00.000Z`,
          viewer: { id: 'parent-test', email: 'parent@example.test', role: 'PARENT', familyId: 'family-test', hasPinCode: true, sessionRef: 'reverse-session' },
          permissions: { canManageFamily: true },
          family: {
            ...storageValues, pointLedger: [], rewardUnlockHistory: [], parentUsers: [],
            familyLeaderboard: { children: [{ id: child.id, name: child.name, avatar: child.avatar }], points: storageValues.points, streaks: storageValues.streaks },
          },
        }),
      });
      return;
    }

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: 'parent-test',
            email: 'parent@example.test',
            role: 'PARENT',
            familyId: 'family-test',
            active: true,
            hasPinCode: true,
          },
        }),
      });
      return;
    }

    if (apiPath === '/api/auth/parent-pin/verify') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    if (apiPath === '/api/auth/parents') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ users: [] }) });
      return;
    }

    if (apiPath === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          children: [{ id: child.id, name: child.name, avatar: child.avatar }],
          points: storageValues.points,
          streaks: storageValues.streaks,
        }),
      });
      return;
    }

    const reverseMatch = apiPath.match(/^\/api\/completions\/([^/]+)\/reverse-approval$/);
    if (reverseMatch) {
      const completion = storageValues.completions.find((item) => item.id === decodeURIComponent(reverseMatch[1]));
      completion.doneByChild = false;
      completion.approvedByParent = false;
      completion.approvedAt = null;
      completion.rejectedByParent = true;
      completion.rejectedAt = `${today}T10:00:00.000Z`;
      completion.reversedAt = `${today}T10:00:00.000Z`;
      storageValues.points = { [child.id]: 4 };
      storageValues.streaks = { [child.id]: { current: 0, best: 1, idealWeeksCount: 0, idealWeeksInRow: 0 } };
      const pointAdjustment = {
        id: 'points-reversal',
        childId: child.id,
        type: 'REVERSAL',
        points: 5,
        delta: -5,
        previousPoints: 9,
        newPoints: 4,
        affectsBalance: false,
        note: 'Cofnięcie zatwierdzenia: Poranne zadanie',
        createdAt: `${today}T10:00:00.000Z`,
      };
      storageValues.pointAdjustments = [pointAdjustment];
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          completion,
          pointAdjustment,
          points: storageValues.points,
          reversal: {
            previousPoints: 9,
            newPoints: 4,
            delta: -5,
            removedPoints: 5,
            childId: child.id,
            taskId: completion.taskId,
            taskTitle: 'Poranne zadanie',
            date: completion.date,
          },
        }),
      });
      return;
    }

    const storageMatch = apiPath.match(/^\/api\/storage\/get\/([^/]+)$/);
    if (storageMatch) {
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: storageValues[key] ?? null }),
      });
      return;
    }

    if (apiPath === '/api/storage/merge') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    await route.continue();
  });

  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /Panel rodzica/ }).click();
  await page.getByPlaceholder('6-cyfrowy PIN').fill('123456');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByText('Zalicz zadania dziecku').waitFor({ state: 'visible', timeout: 10000 });

  const row = page.locator('.task-item').filter({ hasText: 'Poranne zadanie' }).first();
  await row.getByRole('button', { name: 'Cofnij' }).click();
  await page.waitForFunction(() => window.__reverseApprovalDone === true, null, { timeout: 1000 }).catch(() => {});
  await page.waitForTimeout(250);

  assert(dialogMessages.some((message) => message.includes('Cofnąć zatwierdzenie')), 'confirm dialog was not shown');
  assert(dialogMessages.some((message) => message.includes('Efekt punktowy: -5 pkt')), 'result alert was not shown');
  assert.strictEqual(storageValues.completions[0].approvedByParent, false);
  assert.strictEqual(storageValues.points[child.id], 4);

  const updatedRow = page.locator('.task-item').filter({ hasText: 'Poranne zadanie' }).first();
  await updatedRow.getByRole('button', { name: 'Zalicz' }).waitFor({ state: 'visible', timeout: 10000 });
  await page.screenshot({ path: 'tmp/reverse-approval-check.png', fullPage: true });

  await browser.close();
};

(async () => {
  runLogicCheck();
  await runUiCheck();
  await prisma.$disconnect();
  if (staticServer) staticServer.close();
  console.log('Reverse approval logic OK: 9 -> 4 points, no double subtraction after recompute');
  console.log('Reverse approval UI OK: parent can click Cofnij and sees -5 pkt');
  console.log('Screenshot: tmp/reverse-approval-check.png');
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  if (staticServer) staticServer.close();
  process.exit(1);
});
