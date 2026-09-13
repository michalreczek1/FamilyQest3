const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const projectRootDir = path.join(__dirname, '..');
const rootDir = path.join(projectRootDir, 'dist');
const outDir = path.join(projectRootDir, 'tmp', 'parent-voice-command');
const today = '2026-09-13';
const child = {
  id: 'voice-child-filip', name: 'Filip', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '1542', createdAt: '2024-01-01T00:00:00.000Z',
};
const ignacy = {
  id: 'voice-child-ignacy', name: 'Ignacy', avatar: '🧒', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '2681', createdAt: '2024-01-01T00:00:00.000Z',
};
const lucja = {
  id: 'voice-child-lucja', name: 'Łucja', avatar: '👧', activeDays: [1, 2, 3, 4, 5, 6, 7], accessCode: '3712', createdAt: '2024-01-01T00:00:00.000Z',
};
const tasks = [
  { id: 'voice-task-1', childId: child.id, title: 'Zmywarka', tier: 'MIN', points: 2, daysOfWeek: [1, 2, 3, 4, 5, 6, 7], active: true },
  { id: 'voice-task-2', childId: child.id, title: 'Śmieci', tier: 'MIN', points: 1, daysOfWeek: [1, 2, 3, 4, 5, 6, 7], active: true },
  { id: 'voice-task-3', childId: ignacy.id, title: 'Zmywarka Ignacego', tier: 'MIN', points: 2, daysOfWeek: [1, 2, 3, 4, 5, 6, 7], active: true },
];
const state = {
  children: [child, ignacy, lucja], tasks,
  completions: tasks.map((task, index) => ({ id: `voice-completion-${index + 1}`, taskId: task.id, childId: task.childId, date: today, doneByChild: true, approvedByParent: false })),
  extraTasks: [], pointAdjustments: [], pointLedger: [], rewards: [], streaks: { [child.id]: { current: 0, best: 0 }, [ignacy.id]: { current: 0, best: 0 }, [lucja.id]: { current: 0, best: 0 } }, points: { [child.id]: 0, [ignacy.id]: 0, [lucja.id]: 0 },
  rewardUnlocks: [], familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' }, auditLogs: [], dayPointGrants: {}, weekBonusGrants: {}, taskPointGrants: {},
};

const startStaticServer = () => new Promise((resolve) => {
  const server = http.createServer((req, res) => {
    const filePath = path.normalize(path.join(rootDir, decodeURIComponent(new URL(req.url, 'http://127.0.0.1').pathname === '/' ? '/index.html' : new URL(req.url, 'http://127.0.0.1').pathname)));
    if (!filePath.startsWith(rootDir)) return res.writeHead(403).end('Forbidden');
    fs.readFile(filePath, (error, content) => {
      if (error) return res.writeHead(404).end('Not found');
      res.writeHead(200, { 'Content-Type': path.extname(filePath) === '.js' ? 'application/javascript' : path.extname(filePath) === '.css' ? 'text/css' : 'text/html', 'Cache-Control': 'no-store' });
      res.end(content);
    });
  });
  server.listen(0, '127.0.0.1', () => resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` }));
});

const buildPatch = () => ({
  completions: state.completions, extraTasks: state.extraTasks, points: state.points, streaks: state.streaks, pointLedger: [], rewardUnlocks: [], rewardUnlockHistory: [],
  dayPointGrants: {}, weekBonusGrants: {}, taskPointGrants: {}, auditLogs: [], familyLeaderboard: { children: [child, ignacy, lucja], points: state.points, streaks: state.streaks },
});

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const { server, baseUrl } = await startStaticServer();
  const browser = await chromium.launch({ headless: true });
  const apiCalls = { bonuses: [], approvals: [] };
  let failNextBonus = false;
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
    await page.addInitScript(() => {
      class FakeSpeechRecognition {
        start() {
          this.onstart?.();
          setTimeout(() => {
            const result = [{ transcript: window.__testSpeechTranscript || 'dodaj dwa punkty Filipowi za zmywarkę dzisiaj' }];
            result.isFinal = true;
            this.onresult?.({ resultIndex: 0, results: [result] });
            this.onend?.();
          }, 10);
        }
        stop() { this.onend?.(); }
      }
      window.SpeechRecognition = FakeSpeechRecognition;
      window.webkitSpeechRecognition = FakeSpeechRecognition;
    });
    await page.route('**/api/**', async (route) => {
      const apiPath = new URL(route.request().url()).pathname;
      if (apiPath === '/api/auth/me') return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ user: { id: 'parent-test', role: 'PARENT', familyId: 'family-test', email: 'parent@test.local', hasPinCode: true } }) });
      if (apiPath === '/api/auth/parent-pin/verify') return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      if (apiPath === '/api/auth/parents') return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ users: [] }) });
      if (apiPath === '/api/leaderboard') return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ children: [child, ignacy, lucja], points: state.points, streaks: state.streaks }) });
      const storageMatch = apiPath.match(/^\/api\/storage\/get\/([^/]+)$/);
      if (storageMatch) return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ key: decodeURIComponent(storageMatch[1]), value: state[decodeURIComponent(storageMatch[1])] ?? null }) });
      if (apiPath === '/api/point-adjustments' && route.request().method() === 'POST') {
        if (failNextBonus) {
          failNextBonus = false;
          return route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'Testowa odmowa zapisu' }) });
        }
        apiCalls.bonuses.push(JSON.parse(route.request().postData() || '{}'));
        return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ pointAdjustment: {}, points: state.points }) });
      }
      if (apiPath === '/api/completions/approve-bulk' && route.request().method() === 'POST') {
        const body = JSON.parse(route.request().postData() || '{}');
        apiCalls.approvals.push(body);
        state.completions = state.completions.map((completion) => body.ids.includes(completion.id) ? { ...completion, approvedByParent: true } : completion);
        return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ approvedCount: body.ids.length, approvedIds: body.ids, patch: buildPatch() }) });
      }
      return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: apiPath }) });
    });
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: 'Otwórz polecenia głosowe rodzica' }).waitFor();
    await page.getByRole('button', { name: 'Otwórz polecenia głosowe rodzica' }).click();
    await page.getByRole('textbox', { name: 'Polecenie dla rodzica' }).waitFor();
    assert.strictEqual(await page.getByPlaceholder('6-cyfrowy PIN').count(), 0, 'voice commands on the parent home must not request the parent PIN');
    await page.getByRole('button', { name: 'Wydaj polecenie głosowe' }).click();
    await page.getByRole('dialog').getByText(/Dodać 2 pkt dla Filip/).waitFor();
    await page.getByRole('button', { name: 'Potwierdź i wykonaj' }).click();
    await page.getByText('Dodano 2 pkt dla Filip.').waitFor();
    assert.deepStrictEqual(apiCalls.bonuses[0], { childId: child.id, type: 'BONUS', points: 2, note: 'Za zmywarkę (dzisiaj)', sourceDate: today });

    await page.evaluate(() => { window.__testSpeechTranscript = 'dodaj dwa punkty Łucji za grzeczne śniadanie'; });
    await page.getByRole('button', { name: 'Wydaj polecenie głosowe' }).click();
    await page.getByRole('dialog').getByText(/Dodać 2 pkt dla Łucja/).waitFor();
    assert.strictEqual(apiCalls.bonuses.length, 1, 'recognizing Łucji must not save points before confirmation');
    await page.getByRole('button', { name: 'Potwierdź i wykonaj' }).click();
    await page.getByText('Dodano 2 pkt dla Łucja.').waitFor();
    assert.deepStrictEqual(apiCalls.bonuses[1], { childId: lucja.id, type: 'BONUS', points: 2, note: 'Za grzeczne śniadanie (dzisiaj)', sourceDate: today });

    const command = page.getByRole('textbox', { name: 'Polecenie dla rodzica' });
    await command.fill('dodaj 2 punkty Lucji za śniadanie');
    await page.getByRole('button', { name: 'Przygotuj' }).click();
    await page.getByRole('dialog').getByText(/Dodać 2 pkt dla Łucja/).waitFor();
    await page.getByRole('button', { name: 'Anuluj' }).click();
    assert.strictEqual(apiCalls.bonuses.length, 2, 'cancelled command must not save points');

    failNextBonus = true;
    await command.fill('dodaj dwa punkty Łucji za śniadanie');
    await page.getByRole('button', { name: 'Przygotuj' }).click();
    await page.getByRole('button', { name: 'Potwierdź i wykonaj' }).click();
    await page.getByRole('status').getByText(/Testowa odmowa zapisu|Nie udało się zapisać/).waitFor();
    assert.strictEqual(apiCalls.bonuses.length, 2, 'failed request must not report a saved bonus');

    await command.fill('zatwierdź przekazane do zatwierdzenia zadania Filipa');
    await page.getByRole('button', { name: 'Przygotuj' }).click();
    await page.getByRole('dialog').getByText(/Zatwierdzić 2 zadań dla Filip/).waitFor();
    await page.getByRole('button', { name: 'Potwierdź i wykonaj' }).click();
    await page.getByText('Zatwierdzono 2 zadań dla Filip.').waitFor();
    assert.deepStrictEqual(apiCalls.approvals[0], { ids: ['voice-completion-1', 'voice-completion-2'] });

    await command.fill('zatwierdź wszystkie punkty Ignacego');
    await page.getByRole('button', { name: 'Przygotuj' }).click();
    await page.getByRole('dialog').getByText(/Zatwierdzić 1 zadań dla Ignacy/).waitFor();
    await page.getByRole('button', { name: 'Potwierdź i wykonaj' }).click();
    await page.getByText('Zatwierdzono 1 zadań dla Ignacy.').waitFor();
    assert.deepStrictEqual(apiCalls.approvals[1], { ids: ['voice-completion-3'] });

    await command.fill('dodaj dwa punkty za zrobienie zmywarki Ignacemu wczoraj');
    await page.getByRole('button', { name: 'Przygotuj' }).click();
    await page.getByRole('dialog').getByText(/Dodać 2 pkt dla Ignacy/).waitFor();
    await page.getByRole('button', { name: 'Potwierdź i wykonaj' }).click();
    await page.getByText('Dodano 2 pkt dla Ignacy.').waitFor();
    assert.deepStrictEqual(apiCalls.bonuses[2], { childId: ignacy.id, type: 'BONUS', points: 2, note: 'Za zrobienie zmywarki (2026-09-12)', sourceDate: '2026-09-12' });
    await page.screenshot({ path: path.join(outDir, 'voice-command.png'), fullPage: true });
    console.log(`Parent voice command UI OK. Screenshot: ${path.join(outDir, 'voice-command.png')}`);
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => { console.error(error); process.exit(1); });
