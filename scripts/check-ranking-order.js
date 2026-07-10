const { chromium } = require('playwright');
const fs = require('fs');
const http = require('http');
const path = require('path');

const rootDir = path.join(__dirname, '..', 'dist');
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

const children = [
  { id: 'lucja', name: 'Łucja', avatar: '👧', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '1001' },
  { id: 'ignacy', name: 'Ignacy', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '1002' },
  { id: 'franek', name: 'Franek', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '1003' },
  { id: 'filip', name: 'Filip', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '1004' },
  { id: 'jozek', name: 'Józek', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '1005' },
];

const points = {
  lucja: 0,
  ignacy: 27,
  franek: 15,
  filip: 9,
  jozek: 7,
};

const streaks = Object.fromEntries(
  children.map((child) => [
    child.id,
    {
      current: child.id === 'lucja' ? 1 : 0,
      best: child.id === 'lucja' ? 1 : 0,
      idealWeeksCount: 0,
      idealWeeksInRow: 0,
    },
  ]),
);

const storageValues = {
  children,
  tasks: [],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  rewards: [],
  streaks,
  points,
  rewardUnlocks: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
};

const expectedRanking = ['Ignacy', 'Franek', 'Filip', 'Józek', 'Łucja'];

(async () => {
  const baseUrl = process.env.RANKING_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1489, height: 627 } });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;

    if (path === '/api/family-state') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          familyId: 'family-test', version: 1, generatedAt: '2026-05-01T00:00:00.000Z',
          viewer: { id: 'parent-test', email: 'parent@example.test', role: 'PARENT', familyId: 'family-test', hasPinCode: true, sessionRef: 'ranking-session' },
          permissions: { canManageFamily: true },
          family: {
            ...storageValues, pointLedger: [], rewardUnlockHistory: [], parentUsers: [],
            familyLeaderboard: { children, points, streaks },
          },
        }),
      });
      return;
    }

    if (path === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: 'parent-test',
            email: 'parent@example.test',
            role: 'PARENT',
            familyId: 'family-test',
            active: true,
          },
        }),
      });
      return;
    }

    if (path === '/api/auth/parents') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ users: [] }),
      });
      return;
    }

    if (path === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ children, points, streaks }),
      });
      return;
    }

    const storageMatch = path.match(/^\/api\/storage\/get\/([^/]+)$/);
    if (storageMatch) {
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: storageValues[key] ?? null }),
      });
      return;
    }

    if (path === '/api/storage/merge') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ ok: true }),
      });
      return;
    }

    await route.continue();
  });

  await page.goto(baseUrl, { waitUntil: 'networkidle' });

  const rankingCard = page
    .getByText('🏆 Ranking rodzinny')
    .locator('xpath=ancestor::div[contains(@class, "glass-card")][1]');
  await rankingCard.waitFor({ state: 'visible', timeout: 10000 });

  const rows = await rankingCard.locator('.task-item').evaluateAll((nodes) =>
    nodes.map((node) => node.textContent.replace(/\s+/g, ' ').trim()),
  );
  const actualRanking = rows.map((row) => expectedRanking.find((name) => row.includes(name))).filter(Boolean);
  await page.waitForFunction(() => {
    const cards = [...document.querySelectorAll('.glass-card')];
    const ranking = cards.find((card) => card.textContent.includes('Ranking rodzinny'));
    return ranking?.textContent.includes('Łucja') && ranking.textContent.includes('Passa: 0');
  });

  const rowsAfterRecompute = await rankingCard.locator('.task-item').evaluateAll((nodes) =>
    nodes.map((node) => node.textContent.replace(/\s+/g, ' ').trim()),
  );
  const lucjaRow = rowsAfterRecompute.find((row) => row.includes('Łucja')) || '';

  await rankingCard.screenshot({
    path: 'tmp/ranking-order-check.png',
  });

  if (JSON.stringify(actualRanking) !== JSON.stringify(expectedRanking)) {
    throw new Error(`Ranking order mismatch. Expected ${expectedRanking.join(' > ')}, got ${actualRanking.join(' > ')}`);
  }
  if (!lucjaRow.includes('Passa: 0')) {
    throw new Error(`Expected Łucja streak to be recomputed to Passa: 0, got row: ${lucjaRow}`);
  }

  await browser.close();
  if (staticServer) staticServer.close();
  console.log(`Ranking order OK: ${actualRanking.join(' > ')}`);
  console.log('Streak recompute OK: Łucja Passa: 0');
  console.log('Screenshot: tmp/ranking-order-check.png');
})().catch(async (error) => {
  console.error(error);
  if (staticServer) staticServer.close();
  process.exit(1);
});
