# Railway Deploy Checklist

## 1. Podłącz repo
1. Railway -> `New Project`
2. `Deploy from GitHub repo`
3. Wskaż repo: `michalreczek1/FamilyQest3`

## 2. Dodaj bazę
Dodaj usługę `PostgreSQL` w tym samym projekcie.

## 3. Ustaw env (usługa aplikacji)
```env
DATABASE_URL=${{Postgres.DATABASE_URL}}
JWT_SECRET=<losowy-sekret-min-32-znaki>
JWT_EXPIRES_IN=7d
BCRYPT_ROUNDS=12
NODE_ENV=production
CORS_ORIGINS=https://<twoja-domena-railway>
```

## 4. Deploy
Railway użyje `npm start` (zdefiniowane też w `railway.json`):
- `prisma db push`
- `node server.js`

## 5. Weryfikacja po wdrożeniu
- `GET /health` powinno zwrócić `status: ok` i `db: ok`.
- Rejestracja/logowanie rodzica.
- Dodanie dziecka i zadania.

