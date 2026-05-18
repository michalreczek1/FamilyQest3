const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const projectRootDir = path.join(__dirname, '..');
const rootDir = path.join(projectRootDir, 'dist');
const outDir = path.join(projectRootDir, 'tmp', 'bulk-reject-filter');
const today = '2026-05-15';
const child = {
  id: 'bulk-child',
  name: 'Łucja',
  avatar: '👧',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '1542',
  createdAt: '2024-01-01T00:00:00.000Z',
};

const createState = () => ({
  children: [child],
  tasks: [
    {
      id: 'bulk-task-1',
      childId: child.id,
      title: 'Umyj zęby',
      tier: 'MIN',
      points: 1,
      daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
      active: true,
      createdAt: '2024-01-01T00:00:00.000Z',
    },
    {
      id: 'bulk-task-2',
      childId: child.id,
      title: 'Pościel łóżko',
      tier: 'MIN',
      points: 2,
      daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
      active: true,
      createdAt: '2024-01-01T00:00:00.000Z',
    },
  ],
  completions: [
    {
      id: 'bulk-comp-1',
      taskId: 'bulk-task-1',
      childId: child.id,
      date: today,
      doneByChild: true,
      approvedByParent: false,
      rejectedByParent: false,
      createdAt: `${today}T08:00:00.000Z`,
      updatedAt: `${today}T08:00:00.000Z`,
    },
    {
      id: 'bulk-comp-2',
      taskId: 'bulk-task-2',
      childId: child.id,
      date: today,
      doneByChild: true,
      approvedByParent: false,
      rejectedByParent: false,
      createdAt: `${today}T08:10:00.000Z`,
      updatedAt: `${today}T08:10:00.000Z`,
    },
  ],
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
});

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

const installApiMocks = async (page, state, bulkRequests) => {
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: { id: 'parent-test', role: 'PARENT', familyId: 'family-test', email: 'parent@test.local' },
        }),
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
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: state[key] ?? null }),
      });
      return;
    }

    if (apiPath === '/api/storage/merge') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    if (apiPath === '/api/completions/reject-bulk' && route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() || '{}');
      bulkRequests.push(body);
      const requestedIds = new Set(body.ids || []);
      const rejectedIds = [];
      state.completions = state.completions.map((completion) => {
        if (
          !completion.doneByChild ||
          completion.approvedByParent ||
          completion.rejectedByParent ||
          (requestedIds.size > 0 && !requestedIds.has(completion.id)) ||
          (body.childId && completion.childId !== body.childId) ||
          (body.date && completion.date !== body.date)
        ) {
          return completion;
        }
        rejectedIds.push(completion.id);
        return {
          ...completion,
          doneByChild: false,
          approvedByParent: false,
          approvedAt: null,
          rejectedByParent: true,
          rejectedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
      });
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, rejectedCount: rejectedIds.length, rejectedIds, skippedApprovedIds: [] }),
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
  const bulkRequests = [];

  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
    await installApiMocks(page, state, bulkRequests);
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: '🔐 Panel rodzica' }).click();
    await page.getByText('Zadania do zatwierdzenia').waitFor({ state: 'visible', timeout: 10000 });
    await page.getByRole('button', { name: '❌ Odrzuć wg filtra (2)' }).click();
    await page.getByText('Brak zadań do zatwierdzenia').waitFor({ state: 'visible', timeout: 10000 });
    assert.strictEqual(await page.getByRole('button', { name: '❌ Odrzuć wg filtra (2)' }).count(), 0);
    await page.screenshot({ path: path.join(outDir, 'after-bulk-reject.png'), fullPage: true });

    assert.strictEqual(bulkRequests.length, 1, 'bulk reject should call one backend endpoint');
    assert.deepStrictEqual([...bulkRequests[0].ids].sort(), ['bulk-comp-1', 'bulk-comp-2']);
    assert(state.completions.every((completion) => completion.rejectedByParent), 'all visible completions should be rejected');
    console.log(
      JSON.stringify(
        {
          bulkRequests,
          screenshot: path.join(outDir, 'after-bulk-reject.png'),
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
