const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const rootDir = path.join(__dirname, '..', 'dist');
let staticServer = null;

const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
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

const runNetworkErrorCheck = async (browser, baseUrl) => {
  const page = await browser.newPage({ viewport: { width: 900, height: 720 } });
  await page.route('**/api/auth/me', (route) => route.abort('failed'));
  await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
  await page.getByText('Brak połączenia z serwerem domowym').waitFor({ state: 'visible', timeout: 10000 });
  await page.screenshot({ path: 'tmp/hardening-network-error.png', fullPage: true });
  await page.close();
};

const runErrorBoundaryCheck = async (browser, baseUrl) => {
  const page = await browser.newPage({ viewport: { width: 900, height: 720 } });
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') pageErrors.push(message.text());
  });
  await page.addInitScript(() => {
    sessionStorage.setItem('fq_child_session_active', '1');
  });

  const child = {
    id: 'boundary-child',
    name: 'Test',
    avatar: '⭐',
    activeDays: [1, 2, 3, 4, 5, 6, 7],
    accessCode: '1357',
    createdAt: '2026-05-01T00:00:00.000Z',
  };
  const values = {
    children: [child],
    tasks: [],
    completions: [],
    extraTasks: [],
    pointAdjustments: [],
    rewards: [],
    streaks: {},
    points: { [child.id]: 0 },
    rewardUnlocks: [],
    familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
    auditLogs: [],
    dayPointGrants: {},
    weekBonusGrants: {},
    taskPointGrants: {},
  };

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
            familyId: 'family-boundary',
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
          children: [null],
          points: values.points,
          streaks: values.streaks,
        }),
      });
      return;
    }
    const storageMatch = apiPath.match(/^\/api\/storage\/get\/([^/]+)$/);
    if (storageMatch) {
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: values[key] ?? null }),
      });
      return;
    }
    if (apiPath === '/api/storage/merge') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'not mocked' }) });
  });

  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  try {
    await page.getByText('Widok dziecka wymaga odświeżenia').waitFor({ state: 'visible', timeout: 10000 });
  } catch (error) {
    const bodyText = await page.locator('body').innerText().catch(() => '');
    throw new Error(`${error.message}\nBody text:\n${bodyText}\nPage errors:\n${pageErrors.join('\n')}`);
  }
  const refreshButtonVisible = await page.getByRole('button', { name: 'Odśwież panel' }).isVisible();
  assert(refreshButtonVisible, 'error boundary should expose a refresh action');
  await page.screenshot({ path: 'tmp/hardening-error-boundary.png', fullPage: true });
  await page.close();
};

(async () => {
  const baseUrl = process.env.HARDENING_UI_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  try {
    await runNetworkErrorCheck(browser, baseUrl);
    await runErrorBoundaryCheck(browser, baseUrl);
  } finally {
    await browser.close();
    if (staticServer) staticServer.close();
  }
  console.log('Hardening UI OK: network error banner and ErrorBoundary fallback render');
  console.log('Screenshots: tmp/hardening-network-error.png, tmp/hardening-error-boundary.png');
})().catch((error) => {
  console.error(error);
  if (staticServer) staticServer.close();
  process.exit(1);
});
