const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const rootDir = path.join(__dirname, '..', 'dist');
const outDir = path.join(__dirname, '..', 'tmp', 'parent-pin-gate');
let staticServer = null;

const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
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

const emptyState = {
  children: [
    {
      id: 'pin-child',
      name: 'Test',
      avatar: '⭐',
      activeDays: [1, 2, 3, 4, 5, 6, 7],
      createdAt: '2026-05-01T00:00:00.000Z',
    },
  ],
  tasks: [],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  rewards: [],
  streaks: {},
  points: { 'pin-child': 0 },
  rewardUnlocks: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
};

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const baseUrl = process.env.PARENT_PIN_GATE_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  const verifyPayloads = [];
  let wrongPinStreak = 0;

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: 'parent-pin-test',
            email: 'parent@example.test',
            role: 'PARENT',
            familyId: 'family-pin-test',
            active: true,
            hasPinCode: true,
          },
        }),
      });
      return;
    }

    if (apiPath === '/api/auth/parent-pin/verify') {
      const payload = JSON.parse(route.request().postData() || '{}');
      verifyPayloads.push(payload);
      if (payload.pinCode === '123456') {
        wrongPinStreak = 0;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true }),
        });
        return;
      }
      wrongPinStreak += 1;
      const locked = wrongPinStreak >= 3;
      await route.fulfill({
        status: locked ? 429 : 401,
        contentType: 'application/json',
        body: JSON.stringify(locked
          ? { error: 'Za dużo błędnych PIN-ów. Spróbuj za 1 s.', retryAfterSeconds: 1 }
          : { error: 'Nieprawidłowy PIN rodzica', attemptsRemaining: 3 - wrongPinStreak }),
      });
      return;
    }

    if (apiPath === '/api/auth/parents') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          users: [
            {
              id: 'parent-pin-test',
              email: 'parent@example.test',
              active: true,
              role: 'PARENT',
              hasPinCode: true,
              createdAt: '2026-05-01T00:00:00.000Z',
            },
          ],
        }),
      });
      return;
    }

    if (apiPath === '/api/rewards/history') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ rewardUnlockHistory: [] }) });
      return;
    }

    if (apiPath === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          children: emptyState.children.map(({ id, name, avatar }) => ({ id, name, avatar })),
          points: emptyState.points,
          streaks: emptyState.streaks,
        }),
      });
      return;
    }

    const storageMatch = apiPath.match(/^\/api\/storage\/get\/([^/]+)$/);
    if (storageMatch) {
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: emptyState[key] ?? null }),
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
  await page.getByRole('button', { name: /Panel rodzica/ }).click();
  await page.getByRole('heading', { name: 'PIN rodzica' }).waitFor({ state: 'visible', timeout: 10000 });
  await page.getByPlaceholder('6-cyfrowy PIN').fill('111111');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByText('Nieprawidłowy PIN rodzica').waitFor({ state: 'visible', timeout: 10000 });
  assert.strictEqual(await page.getByRole('heading', { name: 'Panel Rodzica' }).isVisible().catch(() => false), false);

  await page.getByPlaceholder('6-cyfrowy PIN').fill('123456');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByRole('heading', { name: 'Panel Rodzica' }).waitFor({ state: 'visible', timeout: 10000 });
  await page.screenshot({ path: path.join(outDir, 'parent-panel-after-pin.png'), fullPage: true });

  await page.getByRole('button', { name: /Powrót/ }).click();
  await page.getByRole('button', { name: /Panel rodzica/ }).waitFor({ state: 'visible', timeout: 10000 });
  await page.getByRole('button', { name: /Panel rodzica/ }).click();
  await page.getByRole('heading', { name: 'PIN rodzica' }).waitFor({ state: 'visible', timeout: 10000 });
  await page.screenshot({ path: path.join(outDir, 'parent-pin-required-again.png'), fullPage: true });

  await page.getByPlaceholder('6-cyfrowy PIN').fill('222222');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByText('Nieprawidłowy PIN rodzica').waitFor({ state: 'visible', timeout: 10000 });
  await page.getByPlaceholder('6-cyfrowy PIN').fill('333333');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByText('Nieprawidłowy PIN rodzica').waitFor({ state: 'visible', timeout: 10000 });
  await page.getByPlaceholder('6-cyfrowy PIN').fill('444444');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByText('Blokada po 3 błędnych PIN-ach').waitFor({ state: 'visible', timeout: 10000 });
  await page.screenshot({ path: path.join(outDir, 'parent-pin-lockout.png'), fullPage: true });
  await page.getByText('Za dużo błędnych PIN-ów').waitFor({ state: 'hidden', timeout: 5000 });
  await page.getByRole('button', { name: 'Wejdź' }).waitFor({ state: 'visible', timeout: 5000 });
  assert.strictEqual(await page.getByPlaceholder('6-cyfrowy PIN').isEnabled(), true);

  assert.deepStrictEqual(verifyPayloads, [
    { pinCode: '111111' },
    { pinCode: '123456' },
    { pinCode: '222222' },
    { pinCode: '333333' },
    { pinCode: '444444' },
  ]);

  await browser.close();
  if (staticServer) staticServer.close();
  console.log('Parent PIN gate OK: wrong PIN blocks, correct PIN opens, re-entry asks again, lockout clears after countdown.');
  console.log('Screenshots: tmp/parent-pin-gate/parent-panel-after-pin.png, tmp/parent-pin-gate/parent-pin-required-again.png, tmp/parent-pin-gate/parent-pin-lockout.png');
})().catch(async (error) => {
  console.error(error);
  if (staticServer) staticServer.close();
  process.exit(1);
});
