/* eslint-disable no-console */

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const projectRootDir = path.join(__dirname, '..');
const rootDir = path.join(projectRootDir, 'dist');
const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

const toLocalDate = (date = new Date()) => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};

const today = toLocalDate();
const child = {
  id: 'child-toggle-latency',
  name: 'Test szybkości',
  avatar: '⚡',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '7412',
  archived: false,
};
const task = {
  id: 'task-toggle-latency',
  childId: child.id,
  title: 'Zadanie z opóźnionym serwerem',
  tier: 'MIN',
  points: 2,
  description: 'Stan UI ma zmienić się przed odpowiedzią API',
  daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
  active: true,
  createdAt: `${today}T00:00:00.000Z`,
};
const state = {
  children: [child],
  tasks: [task],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
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

const startStaticServer = () => new Promise((resolve) => {
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
    resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
  });
});

(async () => {
  const { server, baseUrl } = await startStaticServer();
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  let loggedIn = false;
  let releaseCompletionResponse = null;
  let completionRequestSeen = false;
  let storageGetCount = 0;
  let authMeCount = 0;
  let storageMergeCount = 0;
  const completionResponseGate = new Promise((resolve) => {
    releaseCompletionResponse = resolve;
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      authMeCount += 1;
      await route.fulfill({
        status: loggedIn ? 200 : 401,
        contentType: 'application/json',
        body: JSON.stringify(loggedIn ? {
          user: {
            id: `child:${child.id}`,
            role: 'CHILD',
            familyId: 'family-toggle-latency',
            active: true,
            childId: child.id,
            childName: child.name,
          },
        } : { error: 'Brak tokenu autoryzacji' }),
      });
      return;
    }

    if (apiPath === '/api/auth/login-child') {
      loggedIn = true;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: `child:${child.id}`,
            role: 'CHILD',
            familyId: 'family-toggle-latency',
            childId: child.id,
            childName: child.name,
          },
        }),
      });
      return;
    }

    if (apiPath === '/api/completions' && route.request().method() === 'POST') {
      completionRequestSeen = true;
      await completionResponseGate;
      const now = new Date().toISOString();
      const completion = {
        id: 'completion-toggle-latency',
        taskId: task.id,
        childId: child.id,
        date: today,
        doneByChild: true,
        approvedByParent: false,
        approvedAt: null,
        doneAt: now,
        createdAt: now,
        updatedAt: now,
      };
      state.completions = [completion];
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({ completion }),
      });
      return;
    }

    if (apiPath === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ children: [child], points: state.points, streaks: state.streaks }),
      });
      return;
    }

    const storageMatch = apiPath.match(/^\/api\/storage\/get\/([^/]+)$/);
    if (storageMatch) {
      storageGetCount += 1;
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: state[key] ?? null }),
      });
      return;
    }

    if (apiPath === '/api/storage/merge') {
      storageMergeCount += 1;
    }

    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
  });

  try {
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: 'Dziecko' }).click();
    await page.getByPlaceholder('Kod dziecka (4 cyfry)').fill(child.accessCode);
    await page.getByRole('button', { name: 'Zaloguj dziecko' }).click();
    await page.getByRole('heading', { name: child.name }).waitFor({ timeout: 10000 });

    const taskItem = page.locator('.task-item').filter({ hasText: task.title });
    await taskItem.waitFor();
    const storageGetsBeforeClick = storageGetCount;
    const authMeBeforeClick = authMeCount;
    const startedAt = Date.now();
    await taskItem.click();
    await taskItem.getByText('Czeka na zatwierdzenie rodzica').waitFor({ timeout: 400 });
    const optimisticLatencyMs = Date.now() - startedAt;

    assert(completionRequestSeen, 'click should start POST /api/completions');
    assert(optimisticLatencyMs < 400, `pending state should appear immediately, took ${optimisticLatencyMs} ms`);
    assert.strictEqual(state.completions.length, 0, 'UI should update before the delayed API response mutates server state');

    const completionResponse = page.waitForResponse((response) =>
      response.url().endsWith('/api/completions') && response.request().method() === 'POST',
    );
    releaseCompletionResponse();
    await completionResponse;
    await taskItem.getByText('Czeka na zatwierdzenie rodzica').waitFor();
    await page.waitForTimeout(150);

    assert.strictEqual(authMeCount, authMeBeforeClick, 'task toggle should not reload the session');
    assert.strictEqual(storageGetCount, storageGetsBeforeClick, 'task toggle should not reload the full family snapshot');
    assert.strictEqual(storageMergeCount, 0, 'task toggle should not use storage/merge autosave');

    console.log(`Child task toggle latency OK: optimistic state appeared in ${optimisticLatencyMs} ms`);
  } finally {
    releaseCompletionResponse();
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
