const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');
const { __test, prisma } = require('../server');

const rootDir = path.join(__dirname, '..');
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

const child = {
  id: 'restore-child',
  name: 'Łucja',
  avatar: '👧',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  createdAt: '2024-01-01T00:00:00.000Z',
};

const runLogicCheck = () => {
  const task = {
    id: 'restore-task',
    childId: child.id,
    title: 'Zadanie z przerwą',
    tier: 'MIN',
    points: 3,
    daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
    active: true,
    archivedAt: '2024-05-13T08:00:00.000Z',
    restoredAt: '2024-05-15T08:00:00.000Z',
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-05-15T08:00:00.000Z',
  };
  const makeCompletion = (date, hour) => ({
    id: `restore-completion-${date}`,
    taskId: task.id,
    childId: child.id,
    date,
    doneByChild: true,
    doneAt: `${date}T0${hour}:00:00.000Z`,
    approvedByParent: true,
    approvedAt: `${date}T0${hour + 1}:00:00.000Z`,
    createdAt: `${date}T0${hour}:00:00.000Z`,
    updatedAt: `${date}T0${hour + 1}:00:00.000Z`,
  });
  const state = {
    children: [child],
    tasks: [task],
    completions: [makeCompletion('2024-05-12', 8), makeCompletion('2024-05-14', 8), makeCompletion('2024-05-15', 8)],
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
  };

  __test.recomputePointsAndGrants(state);
  assert.strictEqual(state.points[child.id], 10, 'points should count before archive and after restore, but not archived interval');
  assert(state.pointLedger.some((entry) => entry.date === '2024-05-12' && entry.type === 'TASK_APPROVED'));
  assert(!state.pointLedger.some((entry) => entry.date === '2024-05-14' && entry.type === 'TASK_APPROVED'));
  assert(state.pointLedger.some((entry) => entry.date === '2024-05-15' && entry.type === 'TASK_APPROVED'));
};

const runUiCheck = async () => {
  const storageValues = {
    children: [child],
    tasks: [
      {
        id: 'ui-restore-task',
        childId: child.id,
        title: 'Zadanie w archiwum',
        tier: 'PLUS',
        points: 4,
        description: 'Można przywrócić',
        daysOfWeek: [1, 2, 3, 4, 5],
        active: false,
        archivedAt: '2024-05-13T09:00:00.000Z',
        createdAt: '2024-01-01T00:00:00.000Z',
        updatedAt: '2024-05-13T09:00:00.000Z',
      },
    ],
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
  };
  let restoreCalled = false;
  const baseUrl = process.env.TASK_RESTORE_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
  page.on('dialog', async (dialog) => {
    assert(dialog.message().includes('Przywrócić zadanie'));
    await dialog.accept();
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ user: { id: 'parent-restore-ui', role: 'PARENT', familyId: 'family-restore-ui' } }),
      });
      return;
    }
    if (apiPath === '/api/auth/parents') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ users: [] }) });
      return;
    }
    if (apiPath === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ children: [child], points: {}, streaks: {} }),
      });
      return;
    }
    if (apiPath === '/api/tasks/ui-restore-task/restore') {
      restoreCalled = true;
      const restoredAt = new Date().toISOString();
      storageValues.tasks = storageValues.tasks.map((task) =>
        task.id === 'ui-restore-task'
          ? {
              ...task,
              active: true,
              restoredAt,
              updatedAt: restoredAt,
            }
          : task,
      );
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, task: storageValues.tasks[0], restoredAt }),
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
  await page.getByRole('button', { name: /Zadania/ }).click();
  await page.getByRole('button', { name: /Archiwum/ }).click();
  await page.getByText('Zadanie w archiwum').waitFor({ state: 'visible', timeout: 10000 });
  await page.getByRole('button', { name: /Przywróć/ }).click();
  await page.getByRole('button', { name: /^Aktywne$/ }).click();
  await page.getByText('Zadanie w archiwum').waitFor({ state: 'visible', timeout: 10000 });
  assert.strictEqual(restoreCalled, true, 'restore endpoint should be called');
  await page.screenshot({ path: 'tmp/task-restore-archive-check.png', fullPage: true });
  await browser.close();
};

(async () => {
  runLogicCheck();
  await runUiCheck();
  await prisma.$disconnect();
  if (staticServer) staticServer.close();
  console.log('Task restore logic OK: archived interval remains inactive after restore');
  console.log('Task restore UI OK: parent restores archived task from archive view');
  console.log('Screenshot: tmp/task-restore-archive-check.png');
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  if (staticServer) staticServer.close();
  process.exit(1);
});
