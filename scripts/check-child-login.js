const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const projectRootDir = path.join(__dirname, '..');
const rootDir = path.join(projectRootDir, 'dist');
const outDir = path.join(projectRootDir, 'tmp', 'child-login');
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

const child = {
  id: 'child-login-test',
  name: 'Login Test',
  avatar: '🦊',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '1234',
  archived: false,
};
const oldApprovals = Array.from({ length: 205 }, (_, index) => ({
  id: `old-approved-${index}`,
  taskId: 'old-task',
  childId: child.id,
  date: '2026-01-01',
  doneByChild: true,
  approvedByParent: true,
  approvedAt: '2026-01-02T12:00:00.000Z',
}));

const state = {
  children: [child],
  tasks: [{ id: 'old-task', childId: child.id, title: 'Stare zadanie', tier: 'MIN', points: 1, active: false }],
  completions: oldApprovals,
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

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const { server, baseUrl } = await startStaticServer();
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  let loggedIn = false;
  let loginPayload = null;

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      if (!loggedIn) {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Brak tokenu autoryzacji' }),
        });
        return;
      }
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: `child:${child.id}`,
            role: 'CHILD',
            familyId: 'family-login-test',
            active: true,
            childId: child.id,
            childName: child.name,
          },
        }),
      });
      return;
    }

    if (apiPath === '/api/auth/login-child') {
      loginPayload = JSON.parse(route.request().postData() || '{}');
      loggedIn = loginPayload.accessCode === child.accessCode;
      await route.fulfill({
        status: loggedIn ? 200 : 401,
        contentType: 'application/json',
        body: JSON.stringify(
          loggedIn
            ? {
                token: 'child-token',
                user: {
                  id: `child:${child.id}`,
                  role: 'CHILD',
                  familyId: 'family-login-test',
                  childId: child.id,
                  childName: child.name,
                },
              }
            : { error: 'Nieprawidłowy kod dostępu dziecka' },
        ),
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

    await route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ ok: true }),
    });
  });

  try {
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: 'Dziecko' }).click();
    await page.getByPlaceholder('Kod dziecka (4 cyfry)').fill(child.accessCode);
    await page.getByRole('button', { name: 'Zaloguj dziecko' }).click();
    await page.getByRole('heading', { name: child.name }).waitFor({ timeout: 10000 });
    assert.strictEqual(await page.getByText('Zaliczone zadania').count(), 0, 'historical approvals must be silent on first login');
    assert.strictEqual(await page.locator('.confetti').count(), 0, 'historical approvals must not trigger confetti');
    const seenCount = await page.evaluate((childId) => JSON.parse(localStorage.getItem(`fq_seen_child_updates_v2_${childId}`) || '[]').length, child.id);
    assert.strictEqual(seenCount, 205, 'all historical approvals must be remembered, including those past the old 200-item limit');

    state.completions.push({ id: 'new-approved', taskId: 'old-task', childId: child.id, date: '2026-01-01', doneByChild: true, approvedByParent: true, approvedAt: new Date().toISOString() });
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByText('Zaliczone zadania').waitFor({ state: 'visible' });
    await page.getByText('Rodzic zatwierdził 1 zadanie.').waitFor({ state: 'visible' });
    await page.getByRole('button', { name: 'Super!' }).click();
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: child.name }).waitFor();
    assert.strictEqual(await page.getByText('Zaliczone zadania').count(), 0, 'seen approval must not repeat after another login');

    assert.deepStrictEqual(loginPayload, { accessCode: child.accessCode });
    const calendarDays = await page.locator('.calendar-day').evaluateAll((days) =>
      days.map((day) => {
        const style = getComputedStyle(day);
        return {
          className: day.className,
          backgroundColor: style.backgroundColor,
          borderColor: style.borderColor,
          width: day.getBoundingClientRect().width,
          height: day.getBoundingClientRect().height,
        };
      }),
    );
    assert.strictEqual(calendarDays.length, 14, 'child calendar should render 14 stable day tiles');
    calendarDays.forEach((day, index) => {
      assert(day.className.includes('calendar-day'), `calendar day ${index} should keep the base tile class`);
      assert(
        /\b(na|passed|failed)\b/.test(day.className),
        `calendar day ${index} should have a visual status class, got "${day.className}"`,
      );
      assert.notStrictEqual(day.backgroundColor, 'rgba(0, 0, 0, 0)', `calendar day ${index} should have a visible background`);
      assert.notStrictEqual(day.borderColor, 'rgba(0, 0, 0, 0)', `calendar day ${index} should have a visible border`);
      assert(day.width > 20 && day.height > 20, `calendar day ${index} should keep visible tile dimensions`);
    });
    await page.screenshot({ path: path.join(outDir, 'child-login.png'), fullPage: true });
    console.log('Child login UI OK: single 4-digit code field logs child in through /api/auth/login-child');
    console.log('Screenshot: tmp/child-login/child-login.png');
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
