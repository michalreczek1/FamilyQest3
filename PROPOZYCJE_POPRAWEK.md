# Propozycje poprawek FamilyQuest – plan dla AI (Claude Code)

> Dokument przeznaczony do bezpośredniego skarmienia agentowi AI (np. Claude Code).
> Każdy task jest samodzielny, ma wskazane pliki, linie i kryterium akceptacji.
> Rekomendowana kolejność wykonania: P0 → P1 → P2 → P3. Po każdym taskcie:
> uruchom `npm run lint`, dotknięte `npm run test:*` i, gdy to ma sens, `npm test`.
>
> **Konwencja statusów taska:**
> - `cel:` – co osiągamy
> - `pliki:` – co dotykamy
> - `kroki:` – konkretne zmiany
> - `akceptacja:` – jak zweryfikować
> - `ryzyko:` – co może pójść źle / co trzeba przetestować ręcznie

---

## P0 – KRYTYCZNE (bezpieczeństwo / utrata danych)

### TASK P0-1: Wymuszenie JWT_SECRET we wszystkich środowiskach

- **cel:** Usunąć dev-fallback dla `JWT_SECRET`. Brak sekretu = crash przy starcie.
- **pliki:** `server.js` (~linia 20, 38), `.env.example`, `INSTALLATION.md`
- **kroki:**
  1. W `server.js` znajdź `const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me-in-production'` – zamień na:
     ```js
     const JWT_SECRET = process.env.JWT_SECRET;
     if (!JWT_SECRET || JWT_SECRET.length < 32) {
       throw new Error('JWT_SECRET jest wymagany i musi mieć co najmniej 32 znaki');
     }
     ```
  2. Usuń warunkową walidację `if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET)` – walidacja powyżej już to obsługuje.
  3. W `.env.example` upewnij się, że `JWT_SECRET=` ma komentarz „wymagane, min. 32 znaki, losowe".
  4. W `INSTALLATION.md` dopisz krok wygenerowania sekretu: `openssl rand -hex 32`.
- **akceptacja:**
  - `JWT_SECRET=` (puste) → serwer nie startuje.
  - `JWT_SECRET=short` → serwer nie startuje.
  - Z prawidłowym sekretem testy `npm run test` przechodzą.
- **ryzyko:** stare deployy bez sekretu przestaną startować — to celowe.

### TASK P0-2: Nie wysyłać `pinCode` i `passwordHash` w odpowiedziach API

- **cel:** Wyciekający PIN dziecka / parent w `toPublicUser`.
- **pliki:** `server.js` (~linia 216, miejsca użycia `toPublicUser`)
- **kroki:**
  1. Znajdź `toPublicUser` i usuń `pinCode`, `passwordHash` z zwracanego obiektu.
  2. Dodaj osobną funkcję `toSelfUser(user)` zwracającą maskę `pinCode: !!user.pinCode` (boolean) dla `/api/auth/me`.
  3. Zweryfikuj wszystkie odpowiedzi `res.json({ user: ... })` – wszędzie ma być `toPublicUser` lub `toSelfUser`.
  4. Dodaj test integracyjny: `expect(response.body.user.pinCode).toBeUndefined()`.
- **akceptacja:** żadna odpowiedź `/api/*` nie zwraca pól `pinCode` ani `passwordHash`.
- **ryzyko:** frontend może czytać `user.pinCode` w UI rodzica – sprawdzić `src/components/parent/**`. Jeśli używa, zastąp wywołaniem `/api/users/:id/pin` (dedykowany endpoint pod auth).

### TASK P0-3: Bezpieczne logowanie dziecka bez skanu całej bazy

- **cel:** `POST /api/auth/login-child` nie skanuje wszystkich `FamilyState`.
- **pliki:** `server.js` (~linia 2234–2246), `prisma/schema.prisma`, ew. migracja SQL.
- **kroki:**
  1. Wprowadź indeks GIN/expression dla wyszukiwania po `accessCode` dziecka. Wariant minimalny: w `prisma/schema.prisma` dodaj model `ChildAccessCode { code String @id; familyId String; childId String; }` synchronizowany przy każdej zmianie dziecka (po stronie aplikacji).
  2. Endpoint loguj dziecko przez `prisma.childAccessCode.findUnique({ where: { code } })` → załaduj tylko jedno `FamilyState`.
  3. Migracja: jednorazowy backfill w `scripts/recompute-family-state.js` (lub nowy `scripts/backfill-child-codes.js`).
  4. Rate-limit endpointu (zob. P0-5).
- **akceptacja:**
  - Wstawienie 1000 sztucznych `FamilyState` i pomiar `login-child` < 50 ms.
  - Test integracyjny: błędny kod → 401, brak wycieku liczby rodzin.
- **ryzyko:** desynchronizacja indeksu – dodaj sanity check w `recomputePointsAndGrants`.

### TASK P0-4: Optimistic locking z limitem retry

- **cel:** Brak infinite-retry, jawny 409.
- **pliki:** `server.js` (~linia 681–735 `createSaveStateData`), `src/lib/api.js`, `src/hooks/useAutosave.js`.
- **kroki:**
  1. W `createSaveStateData` ustaw `MAX_RETRIES = 5`. Po wyczerpaniu rzuć `HttpError(409, 'STATE_CONFLICT', { version })`.
  2. W `src/lib/api.js` w `apiRequest` rozpoznaj 409 + body `code: 'STATE_CONFLICT'` → wywołaj refresh (`onConflict?.()` callback).
  3. W `useAutosave.js` po 409 wykonaj pełny refetch stanu (`refetchFamilyState`) i pokaż toast „Dane zostały zaktualizowane – załadowano nową wersję".
- **akceptacja:** Skrypt `scripts/check-family-state-versioning.js` rozszerz o przypadek 5 równoczesnych zapisów → ostatni dostaje 409 i robi refetch.
- **ryzyko:** możliwa utrata zmian, jeśli użytkownik edytował lokalnie – pokaż wyraźny komunikat.

### TASK P0-5: Rate-limit na wrażliwych endpointach mutujących

- **cel:** Ochrona przed brute-force i DoS.
- **pliki:** `server.js` (~linia 1785–1810).
- **kroki:**
  1. Zdefiniuj `strictWriteLimiter` (np. 30/min/IP) i `authLimiter` (10/min/IP) oraz `loginChildLimiter` (5/min/IP).
  2. Załóż limitery na:
     - `POST /api/auth/login`, `POST /api/auth/login-child`, `POST /api/auth/reset-password`
     - `POST /api/completions/approve-bulk`, `POST /api/completions/reject-bulk`
     - `POST /api/point-adjustments`
     - `POST /api/storage/restore-backup`
     - `POST /api/storage/merge`
- **akceptacja:** test `__tests__/api.integration.test.js` – 11. próba logowania w minutę zwraca 429.
- **ryzyko:** za agresywny limit dla rodziny z wieloma użytkownikami z tej samej sieci – kluczuj po `req.user?.id` gdy zalogowany, po IP w przeciwnym razie.

### TASK P0-6: Token resetu hasła w bazie zamiast w `Map`

- **cel:** `passwordResetTokens` (in-memory) ginie po restarcie i nie działa w trybie multi-instancyjnym.
- **pliki:** `server.js` (~linia 2153–2162), `prisma/schema.prisma`.
- **kroki:**
  1. Dodaj model Prisma `PasswordResetToken { tokenHash String @id; userId String; expiresAt DateTime; usedAt DateTime?; }`.
  2. Wystaw token = `crypto.randomBytes(32).toString('base64url')`, w bazie zapisz `sha256(token)`.
  3. Wygaszanie po 30 min (`expiresAt`), `usedAt` markuje jednorazowość.
  4. Wyrzuć `Map` z procesu.
- **akceptacja:** Restart serwera nie unieważnia tokenu wygenerowanego sekundę wcześniej; nie da się go użyć drugi raz.
- **ryzyko:** brak – migracja Prisma, czysty zysk.

---

## P1 – WYSOKIE (poprawność / wydajność)

### TASK P1-1: Mutacja stanu w `recomputePointsAndGrants`

- **cel:** Brak in-place mutacji `data.points`, `data.streaks`.
- **pliki:** `server.js` (~linia 1041–1067).
- **kroki:**
  1. Funkcja `recomputePointsAndGrants(data)` ma zwracać **nową** kopię (`structuredClone` + immutable assignment).
  2. Wywołania `data = recomputePointsAndGrants(data)` zamiast bezstanowej modyfikacji.
  3. Pokrycie testem jednostkowym – małe `data`, dwa wywołania równolegle (await Promise.all) muszą dać identyczny wynik.
- **akceptacja:** test `__tests__/recompute-pure.test.js` (nowy) – idempotencja.
- **ryzyko:** narzut alokacji – akceptowalny przy obecnych rozmiarach stanu.

### TASK P1-2: Logowanie cichych pominięć w recompute

- **cel:** `recomputePointsAndGrants` przestaje milczeć przy invalid completion.
- **pliki:** `server.js` (~linia 1047).
- **kroki:**
  1. Zamiast `return;` użyj `console.warn('[recompute] skipping invalid completion', { completionId, reason })`.
  2. Dodaj licznik `data._diagnostics.skippedCompletions` zwiększany przy każdej takiej iteracji.
  3. Wystaw `GET /api/admin/diagnostics` (tylko rola PARENT) zwracający te liczniki.
- **akceptacja:** test odpalany na zepsutym completion (`taskId` nie istnieje) – w logach pojawia się warning, endpoint diagnostyczny pokazuje licznik.
- **ryzyko:** brak.

### TASK P1-3: Cache obliczeń streak i ranking

- **cel:** Brak rekalkulacji 3650 dni przy każdym GET.
- **pliki:** `server.js` (~linia 2314 `calculateStreakForChildData`), `src/App.jsx` (~241–294).
- **kroki:**
  1. Zapisuj `data.cachedStreaks = { [childId]: { value, computedFromCompletionId } }` w `FamilyState.data`.
  2. Invalidacja: gdy zmienia się completion danego dziecka.
  3. We frontendzie usuń duplikat obliczania (zostaw pojedynczą warstwę – backend źródłem prawdy).
- **akceptacja:** `scripts/check-ranking-order.js` przechodzi; `console.time` dla `/api/leaderboard` < 50 ms dla 5 dzieci × 365 dni.
- **ryzyko:** rozjazd cache – w razie wątpliwości dodaj endpoint `POST /api/admin/recompute` (admin tool).

### TASK P1-4: Request-scoped cache stanu rodziny

- **cel:** Eliminacja N+1 `loadStateData()` w obrębie jednego requestu.
- **pliki:** `server.js` (~linia 737 i wszystkie wywołania `loadStateData`).
- **kroki:**
  1. Middleware `attachFamilyState` ładuje stan raz i przypisuje do `req.familyState`.
  2. Wszystkie handlery używają `req.familyState` zamiast `await loadStateData()`.
  3. Zapis stanu (`saveStateData`) aktualizuje również `req.familyState` (na wypadek kolejnych operacji w tym samym handlerze – rzadkie, ale chroni przed pomyłką).
- **akceptacja:** liczba zapytań `SELECT FROM "FamilyState"` per request = 1 (sprawdź w logach Prismy z `log: ['query']`).
- **ryzyko:** mutacje – `attachFamilyState` musi klonować dane.

### TASK P1-5: Token auth – z localStorage do httpOnly cookie

- **cel:** XSS-resistant auth.
- **pliki:** `server.js` (auth handlery), `src/lib/api.js`, `src/constants.js`.
- **kroki:**
  1. Backend: ustawiaj `Set-Cookie: token=...; HttpOnly; Secure; SameSite=Lax; Path=/`.
  2. CSRF: wprowadź double-submit token (`X-CSRF-Token` w nagłówku + cookie czytelne dla JS, **inne** niż token sesji).
  3. Frontend: usuń `localStorage.setItem(LEGACY_AUTH_TOKEN_KEY, ...)`. `apiRequest` używa `credentials: 'include'`.
  4. Wstecznie kompatybilny tryb – akceptuj header `Authorization: Bearer ...` jeszcze przez 1 release.
- **akceptacja:** ręczny test: po `document.cookie` token niedostępny; po wylogowaniu cookie wyczyszczone.
- **ryzyko:** SameSite=Lax łamie cross-origin – dla embedu trzeba SameSite=None+Secure.

### TASK P1-6: Timeout i retry w `apiRequest`

- **cel:** Fetch nie wisi w nieskończoność; transient 5xx/sieć → retry z backoffem.
- **pliki:** `src/lib/api.js`.
- **kroki:**
  1. `AbortController` z domyślnym timeout 10 s (konfigurowalny per call).
  2. Retry maks 3 razy dla: 502, 503, 504, network error. NIE dla 4xx.
  3. Backoff: 250 ms, 500 ms, 1000 ms + jitter.
  4. Eksport `ApiError` z polami `{ status, code, body, attempt }`.
- **akceptacja:** test jednostkowy (Jest + mock fetch) – 2× 503 → ostateczna odpowiedź 200; 1× 400 → bez retry.
- **ryzyko:** podwójne zapisy – retry tylko dla idempotentnych metod (GET/PUT/DELETE) lub gdy backend zwraca `X-Idempotency-Safe: true`.

### TASK P1-7: Debounce + leader-tab w autosave

- **cel:** Brak burzy zapisów i konfliktów między kartami.
- **pliki:** `src/hooks/useAutosave.js`.
- **kroki:**
  1. Debounce 1500 ms na zapis (zachowując flush-on-unmount).
  2. `BroadcastChannel('familyquest-autosave')` – tylko jedna karta-leader robi zapis; pozostałe nasłuchują zmian.
  3. Obsługa 409 (P0-4) – refetch i ponowny diff.
- **akceptacja:** otwarcie 2 kart, zmiana zadania w jednej → druga widzi zmianę bez ręcznego F5.
- **ryzyko:** złożoność – feature flag `AUTOSAVE_LEADER_TAB=true` na release.

---

## P2 – ŚREDNIE (architektura / DX)

### TASK P2-1: Rozbicie `server.js` (~4000 linii) na moduły

- **cel:** Czytelność i testowalność.
- **pliki:** `server.js` → `src-server/{app.js, auth.js, state.js, completions.js, rewards.js, leaderboard.js, admin.js, middleware/*.js, lib/*.js}`.
- **kroki:**
  1. Każdy endpoint do osobnego routera (`express.Router()`).
  2. Wspólne funkcje (`toPublicUser`, `loadStateData`, `recomputePointsAndGrants`) do `src-server/lib`.
  3. `server.js` ma być cienkim bootstrapem (port, middleware, montowanie routerów).
  4. Wykonaj iteracyjnie, jedna domena = jeden commit.
- **akceptacja:** `wc -l server.js` < 200; testy integracyjne dalej zielone.
- **ryzyko:** błędy importów – CI z `npm test` na każdym kroku.

### TASK P2-2: Rozbicie `src/App.jsx` (1189 linii)

- **cel:** Eliminacja monolitu, redukcja re-renderów.
- **pliki:** `src/App.jsx` → `src/contexts/{AuthContext.jsx, FamilyDataContext.jsx, UIContext.jsx}`.
- **kroki:**
  1. Wydziel auth (login, current user) do `AuthContext`.
  2. Wydziel stan rodziny + autosave do `FamilyDataContext`.
  3. Drobne UI flagi (toasty, modale) → `UIContext`.
  4. `App.jsx` montuje providery i routing.
  5. Każdy tab/panel czyta tylko swój context (`useAuth`, `useFamilyData`).
- **akceptacja:** brak re-renderów `ChildView`/`ParentPanel` przy operacjach nie dotyczących ich domeny (sprawdź React DevTools Profiler).
- **ryzyko:** częste stale closures – pisz testy snapshot dla każdego tab.

### TASK P2-3: `React.memo` + selektory na liściach

- **cel:** Redukcja re-renderów ciężkich list (zadania, completions, leaderboard).
- **pliki:** `src/components/parent/tabs/*.jsx`, `src/components/child/ChildView.jsx`.
- **kroki:**
  1. Dla każdego itemu listy (TaskCard, RewardRow, ApprovalRow) opakuj komponent w `React.memo`.
  2. Handlery przekazuj jako stabilne (`useCallback`) — dopiero po wprowadzeniu kontekstów z P2-2 (inaczej i tak będą tworzone na nowo).
  3. `useMemo` dla list pochodnych w `ChildView.jsx:45-62`.
- **akceptacja:** Profiler: kliknięcie „Akceptuj" na 1 z 50 zadań rerenderuje tylko 1 wiersz.
- **ryzyko:** memoizacja po referencji – pilnuj nowych obiektów props.

### TASK P2-4: Konsolidacja skryptów `check-*.js`

- **cel:** 18 skryptów → jeden runner Playwright + Jest.
- **pliki:** `scripts/check-*.js`, `package.json`, nowy `e2e/*.spec.js`.
- **kroki:**
  1. Dodaj `@playwright/test` (jeśli nie ma) i `playwright.config.js`.
  2. Migruj każdy skrypt do `e2e/<feature>.spec.js` używając `test()` i `expect()`.
  3. W `package.json` zostaw alias: `"test:e2e": "playwright test"`. Stare skrypty usuń lub przenieś do `scripts/legacy/`.
  4. Wspólny setup (mini HTTP server, fixtures) w `e2e/fixtures.js`.
- **akceptacja:** `npm run test:e2e` uruchamia wszystkie e2e jednym wywołaniem, generuje raport HTML.
- **ryzyko:** czas wykonania – włącz `--workers=4`.

### TASK P2-5: ESLint dla Reacta

- **cel:** Łapanie błędów hooków na CI.
- **pliki:** `.eslintrc.cjs`, `package.json`.
- **kroki:**
  1. Dodaj `eslint-plugin-react`, `eslint-plugin-react-hooks`, `eslint-plugin-jsx-a11y`.
  2. Konfiguracja:
     ```js
     extends: [
       'eslint:recommended',
       'plugin:react/recommended',
       'plugin:react-hooks/recommended',
       'plugin:jsx-a11y/recommended'
     ],
     settings: { react: { version: 'detect' } },
     ```
  3. `npm run lint` – napraw wszystkie błędy z `react-hooks/exhaustive-deps` (część z nich to bugi: `App.jsx:241, 711`).
- **akceptacja:** `npm run lint` zero errors.
- **ryzyko:** lawina warningów – wprowadzaj iteracyjnie (`--max-warnings`).

### TASK P2-6: Walidacja Zod dla odpowiedzi API na froncie

- **cel:** Frontend ufa kontraktowi, ale weryfikuje granicę.
- **pliki:** `src/lib/api.js`, nowy `src/lib/schemas.js`.
- **kroki:**
  1. Zdefiniuj `FamilyStateSchema`, `LoginResponseSchema` itp. (Zod, już w dependencies).
  2. W `apiRequest` przyjmuj opcjonalny `schema` – `schema.safeParse(body)`, na fail wywołaj `onSchemaMismatch` (telemetry + fallback).
- **akceptacja:** test snapshot kontraktu – ręczne zepsucie payloadu pokazuje błąd parsingu.
- **ryzyko:** false-positive przy ewolucji API – schemat zostaw permissive (`.passthrough()`).

### TASK P2-7: Cleanup duplikatu schematu DB

- **cel:** Usunąć `postgres-schema.sql` lub jasno opisać że to legacy.
- **pliki:** `postgres-schema.sql`, `INSTALLATION.md`.
- **kroki:**
  1. Jeśli nieużywany – `git rm postgres-schema.sql`.
  2. Jeśli używany do bootstrapu – przepisz na `prisma/migrations/`.
  3. Dodaj nagłówek w pliku informujący o statusie (legacy / canonical).
- **akceptacja:** README/INSTALLATION jednoznacznie wskazują źródło prawdy.
- **ryzyko:** ktoś używał pliku – sprawdź `git log` i `grep -r postgres-schema`.

---

## P3 – NISKIE (kosmetyka, hygiena, długoterminowe)

### TASK P3-1: Literówki w komunikatach błędów

- **pliki:** `server.js` (~3841).
- **kroki:** `'Nieprawidlowe dane merge storage'` → `'Nieprawidłowe dane merge storage'`; `'Blad zapisu storage merge'` → `'Błąd zapisu storage merge'`. Przeskanuj `grep -nE "Blad|Nieprawidlow" server.js` – napraw wszystkie.

### TASK P3-2: `.nvmrc` + Docker

- **pliki:** nowy `.nvmrc`, `Dockerfile`, `docker-compose.yml`.
- **kroki:**
  1. `.nvmrc`: `20.19.0`.
  2. `Dockerfile` wieloetapowy (build vite + runtime node:20-alpine + prisma).
  3. `docker-compose.yml`: serwis `app` + `db: postgres:16`.
- **akceptacja:** `docker compose up` startuje pełny stack lokalnie.

### TASK P3-3: GitHub Actions

- **pliki:** nowy `.github/workflows/ci.yml`.
- **kroki:**
  1. Joby: `lint`, `test`, `test:e2e` (po P2-4), `npm audit --audit-level=high`.
  2. Service postgres dla testów.
  3. Wymóg przejścia jobów dla PR do `main`.

### TASK P3-4: Konfetti i SW – cleanup leaków

- **pliki:** `src/App.jsx:700-708`, `src/main.jsx:38-44`.
- **kroki:**
  1. Konfetti → CSS animation lub komponent z `useEffect` cleanup (kill timer + remove DOM).
  2. Service worker – zamiast „unregister all" rozważ Workbox z `clients.claim()` i precache (oddzielny task – wymaga decyzji UX o offline).

### TASK P3-5: i18n – wydzielenie stringów

- **pliki:** wszystkie komponenty.
- **kroki:** wprowadź `react-intl` lub `i18next`, ekstrahuj polskie stringi do `locales/pl.json`. Akceptacja: brak literałów polskich w JSX (tylko w plikach `locales/*`). To duży task – zaplanuj jako osobny epik.

### TASK P3-6: `familyquest-import-obowiazki.json`

- **pliki:** `familyquest-import-obowiazki.json`.
- **kroki:** zweryfikuj `grep -r familyquest-import` – jeśli nieużywany w kodzie, przenieś do `prisma/fixtures/` z README, albo usuń.

### TASK P3-7: Logi w produkcji

- **pliki:** `src/main.jsx:46-47`, `src/lib/api.js:50`, `src/hooks/useFamilyData.js:144`.
- **kroki:** opakuj logi w `if (import.meta.env.DEV) console.log(...)` lub utwórz `src/lib/log.js` z poziomami.

### TASK P3-8: a11y – focus trap i ARIA-live

- **pliki:** `src/components/common/ModalOverlay.jsx`, wszystkie modale w `src/components/modals/*`, dynamiczne notyfikacje.
- **kroki:**
  1. `react-focus-lock` na overlay.
  2. ESC zamyka modal (jeśli nie ma).
  3. `role="alert" aria-live="polite"` dla toastów i komunikatów punktów.

---

## Kolejność rekomendowana (PR-y)

1. **PR #1 (P0):** P0-1, P0-2, P0-5 (małe, bezpieczne, natychmiastowe).
2. **PR #2 (P0):** P0-6 (migracja Prisma – reset token).
3. **PR #3 (P0):** P0-3 (logowanie dziecka, większe).
4. **PR #4 (P0):** P0-4 + P1-1 + P1-2 (concurrency + immutability + diagnostyka).
5. **PR #5 (P1):** P1-3 + P1-4 (wydajność).
6. **PR #6 (P1):** P1-5 + P1-6 + P1-7 (auth + API + autosave) – feature-flag.
7. **PR #7 (P2):** P2-5 (ESLint) – pociągnie naprawy w innych miejscach.
8. **PR #8+ (P2/P3):** iteracyjnie, każdy task = osobny PR.

---

## Kryteria globalnej akceptacji audytu

- `npm run lint` – zero errors.
- `npm test` – zielone (Jest).
- `npm run test:e2e` (po P2-4) – zielone (Playwright).
- `npm audit --audit-level=high` – zero high/critical.
- Brak `console.log` w bundlu produkcyjnym (`grep -r 'console.log' dist/` puste).
- Profiler: typowa akcja (akceptacja zadania) re-renderuje ≤ 3 komponenty.
- Brak literałów `JWT_SECRET || '...'`, `pinCode`, `passwordHash` w response logach.
- Migracje Prismy idą do przodu (`prisma migrate deploy`) bez błędów.

---

## Notatki dla agenta wykonującego

- Pracuj na branchu `claude/session-ETpAU` (już ustawiony).
- Po każdym taskcie: commit z prefiksem `[P0-1] ...`, `[P1-3] ...`.
- Jeśli task wymaga decyzji architektonicznej (np. P1-5 CSRF strategy) – przerwij i zapytaj użytkownika przez `AskUserQuestion` zamiast zgadywać.
- Nie usuwaj testów, które nie przechodzą po Twojej zmianie – analizuj root cause.
- Nigdy nie pushuj z `--no-verify` ani `--force` na `main`.
- Po zakończeniu PR-a uruchom pełne `npm test` + relewantny `npm run test:<feature>`.
