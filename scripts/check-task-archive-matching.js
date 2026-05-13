const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const request = require('supertest');
const { chromium } = require('playwright');
const { app, __test, prisma } = require('../server');

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

const makeArchiveState = () => {
  const child = {
    id: 'archive-child',
    name: 'Ignacy',
    avatar: '👦',
    activeDays: [1, 2, 3, 4, 5, 6, 7],
    createdAt: '2024-01-01T00:00:00.000Z',
  };
  const task = {
    id: 'archive-task',
    childId: child.id,
    title: 'Historyczne minimum',
    tier: 'MIN',
    points: 3,
    daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
    active: false,
    archivedAt: '2024-05-13T12:00:00.000Z',
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-05-13T12:00:00.000Z',
  };
  return {
    children: [child],
    tasks: [task],
    completions: [
      {
        id: 'archive-completion',
        taskId: task.id,
        childId: child.id,
        date: '2024-05-12',
        doneByChild: true,
        doneAt: '2024-05-12T08:00:00.000Z',
        approvedByParent: true,
        approvedAt: '2024-05-12T09:00:00.000Z',
        createdAt: '2024-05-12T08:00:00.000Z',
        updatedAt: '2024-05-12T09:00:00.000Z',
      },
    ],
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
};

const runLogicCheck = () => {
  const state = makeArchiveState();
  __test.recomputePointsAndGrants(state);
  assert.strictEqual(state.points['archive-child'], 5, 'archived task should keep historical task and day points');
  assert(
    state.pointLedger.some((entry) => entry.type === 'TASK_APPROVED' && entry.sourceId === 'archive-completion'),
    'ledger should keep historical approved task entry',
  );
  assert(
    state.pointLedger.some((entry) => entry.type === 'DAY_PASSED' && entry.date === '2024-05-12'),
    'ledger should keep historical passed-day entry',
  );
};

const runApiCheck = async () => {
  try {
    await prisma.$queryRaw`SELECT 1`;
  } catch (error) {
    console.warn(`Task archive API check skipped: database is unavailable (${error.code || error.name})`);
    return false;
  }

  const suffix = Date.now();
  const parent = {
    email: `archive.${suffix}@familyquest.local`,
    password: 'ArchiveParentPass123!',
    pinCode: '2468',
    familyName: 'Archive Test Family',
  };
  const registerRes = await request(app).post('/api/auth/register').send(parent);
  assert.strictEqual(registerRes.status, 201);
  const parentToken = registerRes.body.token;

  const createChild = async (name) => {
    const response = await request(app)
      .post('/api/children')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({ name, avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7] });
    assert.strictEqual(response.status, 201);
    return response.body.child;
  };
  const firstChild = await createChild(`Archiwum A ${suffix}`);
  const secondChild = await createChild(`Archiwum B ${suffix}`);

  const createTask = async (childId) => {
    const response = await request(app)
      .post('/api/tasks')
      .set('Authorization', `Bearer ${parentToken}`)
      .send({
        childId,
        title: 'Wspólne czytanie',
        tier: 'MIN',
        points: 3,
        description: 'Ten sam zestaw',
        daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
      });
    assert.strictEqual(response.status, 201);
    return response.body.task;
  };
  const firstTask = await createTask(firstChild.id);
  const secondTask = await createTask(secondChild.id);

  const archiveRes = await request(app)
    .post(`/api/tasks/${firstTask.id}/archive-matching`)
    .set('Authorization', `Bearer ${parentToken}`);
  assert.strictEqual(archiveRes.status, 200);
  assert.strictEqual(archiveRes.body.archivedCount, 2);
  assert(archiveRes.body.archivedTaskIds.includes(firstTask.id));
  assert(archiveRes.body.archivedTaskIds.includes(secondTask.id));

  const activeFirstTasks = await request(app)
    .get(`/api/tasks?childId=${encodeURIComponent(firstChild.id)}`)
    .set('Authorization', `Bearer ${parentToken}`);
  assert.strictEqual(activeFirstTasks.status, 200);
  assert.strictEqual(activeFirstTasks.body.tasks.some((task) => task.id === firstTask.id), false);

  const archivedTasks = await request(app)
    .get('/api/tasks?includeArchived=true')
    .set('Authorization', `Bearer ${parentToken}`);
  assert.strictEqual(archivedTasks.status, 200);
  const firstArchived = archivedTasks.body.tasks.find((task) => task.id === firstTask.id);
  const secondArchived = archivedTasks.body.tasks.find((task) => task.id === secondTask.id);
  assert.strictEqual(firstArchived.active, false);
  assert.strictEqual(secondArchived.active, false);
  assert(firstArchived.archivedAt);
  assert(secondArchived.archivedAt);
  return true;
};

const runUiCheck = async () => {
  const children = [
    { id: 'ui-child-1', name: 'Łucja', avatar: '👧', activeDays: [1, 2, 3, 4, 5, 6, 7] },
    { id: 'ui-child-2', name: 'Ignacy', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7] },
  ];
  const storageValues = {
    children,
    tasks: children.map((child, index) => ({
      id: `ui-task-${index + 1}`,
      childId: child.id,
      title: 'Wspólne czytanie',
      tier: 'MIN',
      points: 3,
      description: 'Ten sam zestaw',
      daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
      active: true,
      createdAt: '2024-01-01T00:00:00.000Z',
    })),
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
  let archiveCalled = false;

  const baseUrl = process.env.TASK_ARCHIVE_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
  page.on('dialog', async (dialog) => {
    assert(dialog.message().includes('u wszystkich dzieci'));
    await dialog.accept();
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ user: { id: 'parent-ui', role: 'PARENT', familyId: 'family-ui' } }),
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
        body: JSON.stringify({ children, points: {}, streaks: {} }),
      });
      return;
    }

    if (apiPath === '/api/tasks/ui-task-1/archive-matching') {
      archiveCalled = true;
      const archivedAt = new Date().toISOString();
      storageValues.tasks = storageValues.tasks.map((task) => ({
        ...task,
        active: false,
        archivedAt,
        updatedAt: archivedAt,
      }));
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          archivedTaskIds: ['ui-task-1', 'ui-task-2'],
          archivedCount: 2,
          archivedAt,
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
  await page.getByRole('button', { name: /Zadania/ }).click();
  await page.getByRole('button', { name: /U wszystkich/ }).first().click();
  await page.waitForFunction(() => !document.body.innerText.includes('U wszystkich'));
  assert.strictEqual(archiveCalled, true);
  await page.screenshot({ path: 'tmp/task-archive-matching-check.png', fullPage: true });
  await browser.close();
};

(async () => {
  runLogicCheck();
  const apiChecked = await runApiCheck();
  await runUiCheck();
  await prisma.$disconnect();
  if (staticServer) staticServer.close();
  console.log('Task archive logic OK: historical points remain after archivedAt');
  console.log(
    apiChecked
      ? 'Task archive API OK: matching active task definitions archive together'
      : 'Task archive API SKIPPED locally: database unavailable',
  );
  console.log('Task archive UI OK: parent can archive matching tasks with one button');
  console.log('Screenshot: tmp/task-archive-matching-check.png');
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  if (staticServer) staticServer.close();
  process.exit(1);
});
