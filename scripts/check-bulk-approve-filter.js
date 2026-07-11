const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const projectRootDir = path.join(__dirname, '..');
const rootDir = path.join(projectRootDir, 'dist');
const outDir = path.join(projectRootDir, 'tmp', 'bulk-approve-filter');
const today = '2026-05-15';
const child = {
  id: 'bulk-child',
  name: 'Łucja',
  avatar: '👧',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '1542',
  createdAt: '2024-01-01T00:00:00.000Z',
};

const createState = () => {
  const tasks = Array.from({ length: 23 }, (_, index) => ({
      id: `bulk-task-${index + 1}`,
      childId: child.id,
      title: `Zadanie do zatwierdzenia ${index + 1}`,
      tier: 'MIN',
      points: (index % 3) + 1,
      daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
      active: true,
      createdAt: '2024-01-01T00:00:00.000Z',
    }));
  const completions = tasks.map((task, index) => ({
      id: `bulk-comp-${index + 1}`,
      taskId: task.id,
      childId: child.id,
      date: today,
      doneByChild: true,
      approvedByParent: false,
      createdAt: `${today}T08:${String(index).padStart(2, '0')}:00.000Z`,
      updatedAt: `${today}T08:${String(index).padStart(2, '0')}:00.000Z`,
    }));
  return {
    children: [child],
    tasks,
    completions,
    extraTasks: [],
    pointAdjustments: [],
    pointLedger: [],
    rewards: [],
    streaks: { [child.id]: { current: 0, best: 0, idealWeeksCount: 0, idealWeeksInRow: 0 } },
    points: { [child.id]: 0 },
    rewardUnlocks: [],
    familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
    auditLogs: [],
    dayPointGrants: {},
    weekBonusGrants: {},
    taskPointGrants: {},
  };
};

const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
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
      resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` });
    });
  });

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const buildStatePatch = (state) => ({
  completions: state.completions,
  extraTasks: state.extraTasks,
  points: state.points,
  streaks: state.streaks,
  pointLedger: state.pointLedger,
  rewardUnlocks: state.rewardUnlocks,
  rewardUnlockHistory: [],
  dayPointGrants: state.dayPointGrants,
  weekBonusGrants: state.weekBonusGrants,
  taskPointGrants: state.taskPointGrants,
  auditLogs: state.auditLogs,
  familyLeaderboard: {
    children: [{ id: child.id, name: child.name, avatar: child.avatar }],
    points: state.points,
    streaks: state.streaks,
  },
});

const installApiMocks = async (page, state, metrics) => {
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: { id: 'parent-test', role: 'PARENT', familyId: 'family-test', email: 'parent@test.local', hasPinCode: true },
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
          points: state.points,
          streaks: state.streaks,
        }),
      });
      return;
    }

    const storageMatch = apiPath.match(/^\/api\/storage\/get\/([^/]+)$/);
    if (storageMatch) {
      metrics.storageGets += 1;
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: state[key] ?? null }),
      });
      return;
    }

    if (apiPath === '/api/storage/merge') {
      metrics.mergeRequests += 1;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    if (apiPath === '/api/completions/approve-bulk' && route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() || '{}');
      metrics.bulkRequests.push(body);
      const requestedIds = new Set(body.ids || []);
      const approvedIds = [];
      state.completions = state.completions.map((completion) => {
        if (
          !completion.doneByChild ||
          completion.approvedByParent ||
          (requestedIds.size > 0 && !requestedIds.has(completion.id)) ||
          (body.childId && completion.childId !== body.childId) ||
          (body.date && completion.date !== body.date)
        ) {
          return completion;
        }
        approvedIds.push(completion.id);
        return {
          ...completion,
          approvedByParent: true,
          approvedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
      });
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, approvedCount: approvedIds.length, approvedIds, patch: buildStatePatch(state) }),
      });
      return;
    }

    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: apiPath }) });
  });
};

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const { server, baseUrl } = await startStaticServer();
  const browser = await chromium.launch({ headless: true });
  const state = createState();
  const metrics = {
    bulkRequests: [],
    storageGets: 0,
    mergeRequests: 0,
  };

  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
    await installApiMocks(page, state, metrics);
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: '🔐 Panel rodzica' }).click();
    await page.getByPlaceholder('6-cyfrowy PIN').fill('123456');
    await page.getByRole('button', { name: 'Wejdź' }).click();
    await page.getByText('Zadania do zatwierdzenia').waitFor({ state: 'visible', timeout: 10000 });
    const storageGetsAfterInitialLoad = metrics.storageGets;
    await page.getByRole('button', { name: '✅ Zatwierdź wg filtra (23)' }).click();
    await page.getByText('Brak zadań do zatwierdzenia').waitFor({ state: 'visible', timeout: 10000 });
    assert.strictEqual(await page.getByRole('button', { name: /Zatwierdź wg filtra/ }).count(), 0);
    await page.screenshot({ path: path.join(outDir, 'after-bulk-approve.png'), fullPage: true });

    assert.strictEqual(metrics.bulkRequests.length, 1, 'bulk approve should call one backend endpoint');
    assert.strictEqual(metrics.bulkRequests[0].ids.length, 23, 'bulk approve should include every visible completion');
    assert.strictEqual(metrics.storageGets, storageGetsAfterInitialLoad, 'patch should avoid a full storage reload after bulk approve');
    const mergeRequestsAfterAction = metrics.mergeRequests;
    await wait(5600);
    assert(metrics.storageGets > storageGetsAfterInitialLoad, 'silent polling refresh should still read fresh server state');
    assert.strictEqual(metrics.mergeRequests, mergeRequestsAfterAction, 'silent polling refresh must not autosave loaded approval state');
    assert.strictEqual(await page.getByText('Brak zadań do zatwierdzenia').count(), 1, 'empty approval state should stay stable after polling refresh');
    assert(state.completions.every((completion) => completion.approvedByParent), 'all visible completions should be approved');
    console.log(
      JSON.stringify(
        {
          bulkRequests: metrics.bulkRequests,
          storageGets: metrics.storageGets,
          mergeRequests: metrics.mergeRequests,
          screenshot: path.join(outDir, 'after-bulk-approve.png'),
        },
        null,
        2,
      ),
    );
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
