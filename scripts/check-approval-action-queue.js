const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const projectRootDir = path.join(__dirname, '..');
const rootDir = path.join(projectRootDir, 'dist');
const outDir = path.join(projectRootDir, 'tmp', 'approval-action-queue');
const today = '2026-05-15';

const child = {
  id: 'queue-child',
  name: 'Franek',
  avatar: '👦',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '3452',
  createdAt: '2024-01-01T00:00:00.000Z',
};

const createState = () => ({
  children: [child],
  tasks: [1, 2, 3].map((index) => ({
    id: `queue-task-${index}`,
    childId: child.id,
    title: `Zadanie do odrzucenia ${index}`,
    tier: 'MIN',
    points: index,
    daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
    active: true,
    createdAt: '2024-01-01T00:00:00.000Z',
  })),
  completions: [1, 2, 3].map((index) => ({
    id: `queue-comp-${index}`,
    taskId: `queue-task-${index}`,
    childId: child.id,
    date: today,
    doneByChild: true,
    approvedByParent: false,
    rejectedByParent: false,
    createdAt: `${today}T08:0${index}:00.000Z`,
    updatedAt: `${today}T08:0${index}:00.000Z`,
  })),
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
          user: { id: 'parent-queue-test', role: 'PARENT', familyId: 'family-queue-test', email: 'parent@test.local', hasPinCode: true },
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

    if (apiPath === '/api/rewards/history') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ rewardUnlockHistory: [] }),
      });
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

    if (apiPath === '/api/completions/reject-bulk' && route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() || '{}');
      metrics.bulkRejectRequests.push(body);
      const requestedIds = new Set(body.ids || []);
      const rejectedIds = [];
      await wait(700);
      state.completions = state.completions.map((completion) => {
        if (
          !completion.doneByChild ||
          completion.approvedByParent ||
          completion.rejectedByParent ||
          (requestedIds.size > 0 && !requestedIds.has(completion.id))
        ) {
          return completion;
        }
        rejectedIds.push(completion.id);
        return {
          ...completion,
          doneByChild: false,
          approvedByParent: false,
          rejectedByParent: true,
          rejectedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
      });
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          rejectedCount: rejectedIds.length,
          rejectedIds,
          skippedApprovedIds: [],
          statePatch: buildStatePatch(state),
        }),
      });
      return;
    }

    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: apiPath }) });
  });
};

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const { server, baseUrl: localBaseUrl } = await startStaticServer();
  const baseUrl = process.env.APPROVAL_ACTION_QUEUE_BASE_URL || localBaseUrl;
  const browser = await chromium.launch({ headless: true });
  const state = createState();
  const metrics = {
    bulkRejectRequests: [],
    storageGets: 0,
    mergeRequests: 0,
  };
  const dialogMessages = [];

  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
    page.on('dialog', async (dialog) => {
      dialogMessages.push(dialog.message());
      await dialog.accept();
    });
    await installApiMocks(page, state, metrics);
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: /Panel rodzica/ }).click();
    await page.getByPlaceholder('6-cyfrowy PIN').fill('123456');
    await page.getByRole('button', { name: 'Wejdź' }).click();
    await page.getByText('Zadania do zatwierdzenia').waitFor({ state: 'visible', timeout: 10000 });

    const rejectButtons = await page.locator('.task-item').getByRole('button', { name: /Odrzuć/ }).elementHandles();
    assert.strictEqual(rejectButtons.length, 3, 'test fixture should show three reject buttons');
    const storageGetsAfterInitialLoad = metrics.storageGets;
    const rejectButtonLocator = page.locator('.task-item').getByRole('button', { name: /Odrzuć/ });
    await rejectButtonLocator.evaluateAll((buttons) => {
      buttons.forEach((button) => button.click());
    });

    await page.waitForFunction(() => document.body.innerText.includes('Brak zadań do zatwierdzenia'), null, {
      timeout: 250,
    });
    assert(state.completions.every((completion) => !completion.rejectedByParent), 'UI should clear before the delayed backend response updates state');
    await wait(1200);

    try {
      await page.waitForFunction(() => document.body.innerText.includes('Brak zadań do zatwierdzenia'), null, {
        timeout: 10000,
      });
    } catch (error) {
      await page.screenshot({ path: path.join(outDir, 'failure.png'), fullPage: true });
      console.log(
        JSON.stringify(
          {
            metrics,
            completions: state.completions,
            bodyText: (await page.locator('body').innerText()).slice(0, 2000),
            screenshot: path.join(outDir, 'failure.png'),
          },
          null,
          2,
        ),
      );
      throw error;
    }
    await page.screenshot({ path: path.join(outDir, 'after-rapid-rejects.png'), fullPage: true });

    assert.strictEqual(metrics.bulkRejectRequests.length, 1, 'rapid parent actions should be batched into one backend request');
    assert.deepStrictEqual([...metrics.bulkRejectRequests[0].ids].sort(), ['queue-comp-1', 'queue-comp-2', 'queue-comp-3']);
    assert.strictEqual(metrics.storageGets, storageGetsAfterInitialLoad, 'statePatch should avoid a full storage reload after batched action');
    const mergeRequestsAfterAction = metrics.mergeRequests;
    await wait(5600);
    assert(metrics.storageGets > storageGetsAfterInitialLoad, 'silent polling refresh should still read fresh server state');
    assert.strictEqual(metrics.mergeRequests, mergeRequestsAfterAction, 'silent polling refresh must not echo the loaded snapshot back through autosave');
    assert(!dialogMessages.some((message) => message.includes('Stan rodziny zmienił')), 'version conflict dialog should not appear');
    assert(state.completions.every((completion) => completion.rejectedByParent), 'all clicked completions should be rejected');

    console.log(
      JSON.stringify(
        {
          bulkRejectRequests: metrics.bulkRejectRequests,
          storageGets: metrics.storageGets,
          mergeRequests: metrics.mergeRequests,
          dialogs: dialogMessages,
          screenshot: path.join(outDir, 'after-rapid-rejects.png'),
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
