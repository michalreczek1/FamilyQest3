const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const rootDir = path.join(__dirname, '..');
const outDir = path.join(rootDir, 'tmp', 'extra-task-resubmit');
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

const getLocalDateString = () => {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
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
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });

const child = {
  id: 'extra-child',
  name: 'Łucja',
  avatar: '👧',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '1542',
  createdAt: '2024-01-01T00:00:00.000Z',
};

const today = getLocalDateString();
const createState = () => ({
  children: [child],
  tasks: [],
  completions: [],
  extraTasks: [
    {
      id: 'extra-approved',
      childId: child.id,
      title: 'Wieczorna zmywarka',
      date: '2026-05-15',
      status: 'APPROVED',
      points: 1,
      submittedAt: '2026-05-15T17:00:00.000Z',
      updatedAt: '2026-05-15T18:00:00.000Z',
    },
    {
      id: 'extra-rejected',
      childId: child.id,
      title: 'Test odrzucony',
      date: '2026-05-14',
      status: 'REJECTED',
      points: null,
      submittedAt: '2026-05-14T17:00:00.000Z',
      updatedAt: '2026-05-14T18:00:00.000Z',
    },
    {
      id: 'extra-pending',
      childId: child.id,
      title: 'Czeka już na rodzica',
      date: today,
      status: 'PENDING',
      points: null,
      submittedAt: `${today}T17:00:00.000Z`,
      updatedAt: `${today}T17:00:00.000Z`,
    },
  ],
  pointAdjustments: [],
  pointLedger: [],
  rewards: [],
  streaks: { [child.id]: { current: 0, best: 0, idealWeeksCount: 0, idealWeeksInRow: 0 } },
  points: { [child.id]: 8 },
  rewardUnlocks: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
});

const installApiMocks = async (page, state, posts) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('fq_child_session_active', '1');
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: `child:${child.id}`,
            role: 'CHILD',
            familyId: 'family-test',
            childId: child.id,
            childName: child.name,
          },
        }),
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

    if (apiPath === '/api/extra-tasks' && route.request().method() === 'POST') {
      const body = JSON.parse(route.request().postData() || '{}');
      posts.push(body);
      const now = new Date().toISOString();
      const extraTask = {
        id: `extra-repeat-${posts.length}`,
        childId: body.childId,
        title: body.title,
        date: body.date,
        status: 'PENDING',
        points: null,
        submittedAt: now,
        createdAt: now,
        updatedAt: now,
      };
      state.extraTasks = [extraTask, ...state.extraTasks];
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({ extraTask }),
      });
      return;
    }

    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: apiPath }) });
  });
};

const getLayoutMetrics = (page) =>
  page.evaluate(() => {
    const width = window.innerWidth;
    const bad = [];
    document.querySelectorAll('.extra-task-history-list .task-item, .extra-task-history-list .btn, .extra-task-history-list .badge').forEach((node) => {
      const rect = node.getBoundingClientRect();
      if (rect.left < -1 || rect.right > width + 1) {
        bad.push({
          text: node.textContent.trim().slice(0, 80),
          left: Math.round(rect.left),
          right: Math.round(rect.right),
          width: Math.round(rect.width),
        });
      }
    });
    return {
      width,
      scrollWidth: document.documentElement.scrollWidth,
      bad,
    };
  });

const closeStartupDialogs = async (page) => {
  const dialogs = page.getByRole('dialog');
  const count = await dialogs.count();
  for (let index = 0; index < count; index += 1) {
    const dialog = dialogs.nth(index);
    if (!(await dialog.isVisible().catch(() => false))) continue;
    const closeButtons = dialog.getByRole('button');
    const closeCount = await closeButtons.count();
    if (closeCount > 0) {
      await closeButtons.nth(closeCount - 1).click();
    }
  }
};

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const { server, baseUrl } = await startStaticServer();
  const browser = await chromium.launch({ headless: true });
  const posts = [];
  const state = createState();

  try {
    const desktop = await browser.newPage({ viewport: { width: 1280, height: 760 } });
    await installApiMocks(desktop, state, posts);
    await desktop.goto(baseUrl, { waitUntil: 'networkidle' });
    await closeStartupDialogs(desktop);
    await desktop.locator('.extra-task-history-list').getByText('Wieczorna zmywarka').waitFor({ state: 'visible', timeout: 10000 });
    await desktop.getByText('Czeka już na rodzica').waitFor({ state: 'visible', timeout: 10000 });
    assert.strictEqual(await desktop.getByRole('button', { name: '↻ Zgłoś ponownie' }).count(), 2);
    const approvedItem = desktop.locator('.extra-task-history-list .task-item').filter({ hasText: 'Wieczorna zmywarka' });
    await approvedItem.getByRole('button', { name: '↻ Zgłoś ponownie' }).click();
    await desktop.getByText('Czeka', { exact: true }).waitFor({ state: 'visible', timeout: 10000 });
    assert.strictEqual(posts.length, 1, 'resubmit should create exactly one extra task');
    assert.deepStrictEqual(posts[0], {
      childId: child.id,
      title: 'Wieczorna zmywarka',
      date: today,
    });
    const desktopMetrics = await getLayoutMetrics(desktop);
    await desktop.screenshot({ path: path.join(outDir, 'desktop.png'), fullPage: true });
    await desktop.close();

    const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
    await installApiMocks(mobile, state, posts);
    await mobile.goto(baseUrl, { waitUntil: 'networkidle' });
    await closeStartupDialogs(mobile);
    await mobile.getByText('Zadanie dodatkowe').waitFor({ state: 'visible', timeout: 10000 });
    assert.strictEqual(await mobile.getByRole('button', { name: '↻ Zgłoś ponownie' }).count(), 2);
    const mobileRepeatButtons = await mobile.getByRole('button', { name: '↻ Zgłoś ponownie' }).all();
    for (const button of mobileRepeatButtons) {
      assert.strictEqual(await button.isVisible(), true, 'mobile resubmit buttons should be visible');
    }
    const mobileMetrics = await getLayoutMetrics(mobile);
    await mobile.screenshot({ path: path.join(outDir, 'mobile.png'), fullPage: true });
    await mobile.close();

    const failures = [desktopMetrics, mobileMetrics].filter(
      (metrics) => metrics.scrollWidth > metrics.width + 1 || metrics.bad.length > 0,
    );
    console.log(
      JSON.stringify(
        {
          posts,
          screenshots: {
            desktop: path.join(outDir, 'desktop.png'),
            mobile: path.join(outDir, 'mobile.png'),
          },
          metrics: { desktop: desktopMetrics, mobile: mobileMetrics },
        },
        null,
        2,
      ),
    );
    assert.strictEqual(failures.length, 0, 'extra task history controls should not overflow');
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
