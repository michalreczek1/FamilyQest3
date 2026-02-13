# FamilyQuest 3

Aplikacja rodzinna do zarządzania zadaniami dzieci, akceptacji przez rodzica, passy, punktów i nagród.

## Najważniejsze funkcje
- Rejestracja/logowanie rodzica (JWT).
- Logowanie dziecka kodem 4-cyfrowym.
- Profile dzieci: dodawanie, edycja (emoji, dni aktywne, kod), archiwizacja.
- Zadania: `MIN`, `PLUS`, `WEEKLY`.
- Oznaczanie wykonania przez dziecko + akceptacja/odrzucanie przez rodzica.
- Zatwierdzanie zbiorcze z filtrami (dziecko/data).
- Nagrody i odblokowania.
- Cel rodzinny.
- Ranking dzieci (🥇🥈🥉).
- PWA + Service Worker.

## Stack
- Frontend: `index.html` (React 18 przez CDN, Babel standalone).
- Backend: Node.js + Express (`server.js`).
- Baza danych: PostgreSQL + Prisma.
- Testy: Jest + Supertest + smoke script.

## Wymagania
- Node.js 18+
- npm 9+
- PostgreSQL (lokalnie lub Railway)

## Szybki start lokalnie
1. Zainstaluj zależności:
```bash
npm install
```

2. Utwórz `.env` na podstawie `.env.example` i ustaw minimum:
```env
DATABASE_URL="postgresql://user:pass@localhost:5432/familyquest?schema=public"
JWT_SECRET="bardzo-dlugi-sekret-min-32-znaki"
NODE_ENV=development
PORT=3010
```

3. Wypchnij schemat i wygeneruj klienta Prisma:
```bash
npx prisma db push
```

4. (Opcjonalnie) seed konta rodzica:
```env
AUTO_SEED=true
SEED_PARENT_EMAIL=rodzic@familyquest.local
SEED_PARENT_PASSWORD=Haslo123!
SEED_PARENT_PIN=1234
SEED_FAMILY_NAME=Rodzina Testowa
```
```bash
npm run db:seed
```

5. Uruchom aplikację:
```bash
npm start
```

Aplikacja: `http://localhost:3010`

## Testy

### Testy integracyjne API (Jest/Supertest)
```bash
npm test
```

### Smoke E2E (żywy backend)
Wymaga działającej aplikacji (domyślnie `http://127.0.0.1:3010`):
```bash
npm run test:smoke
```

Możesz podać inny URL:
```bash
SMOKE_BASE_URL=https://twoja-apka.up.railway.app npm run test:smoke
```

## Deployment na Railway

Repo jest przygotowane pod Railway:
- `npm start` uruchamia:
  - `prisma db push`
  - `node server.js`
- `railway.json` ustawia:
  - `startCommand: npm start`
  - healthcheck: `GET /health`

### Kroki
1. Podłącz repozytorium w Railway (`New Project -> Deploy from GitHub repo`).
2. Dodaj usługę PostgreSQL.
3. Ustaw zmienne środowiskowe w usłudze aplikacji:
```env
DATABASE_URL=${{Postgres.DATABASE_URL}}
JWT_SECRET=<losowy-dlugi-sekret>
JWT_EXPIRES_IN=7d
BCRYPT_ROUNDS=12
NODE_ENV=production
CORS_ORIGINS=https://<twoja-domena-railway>
```
4. Wygeneruj domenę Railway i sprawdź:
- `GET /health` -> `{"status":"ok","db":"ok",...}`

## Struktura projektu
- `index.html` - frontend aplikacji.
- `server.js` - backend API.
- `prisma/schema.prisma` - schema bazy.
- `prisma/seed.js` - seed konta rodzica.
- `service-worker.js` - cache offline/PWA.
- `__tests__/api.integration.test.js` - test integracyjny API.
- `scripts/smoke-e2e.js` - smoke test E2E.

## Uwaga dot. kodowania
Projekt używa UTF-8 (polskie znaki i emoji w UI/danych).

