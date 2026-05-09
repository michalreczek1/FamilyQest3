# Audyt logiki aplikacji FamilyQuest

Data audytu: 2026-05-09  
Ostatnia aktualizacja: 2026-05-09

Zakres: backend `server.js`, uruchamiany frontend `familyquest-app.compiled.js`, `index.html`, `prisma/schema.prisma`, testy integracyjne, smoke i Playwrightowy test rankingu.

## Status Po Ostatnich Zmianach

Naprawiony zostal krytyczny pakiet logiki punktow i rankingu:

- Ranking rodzinny sortuje po punktach jako glownym wyniku.
- Ekran `Ranking rodzinny` na wyborze profilu uzywa danych z `/api/leaderboard`, a nie tylko lokalnej kolejnosci `children`.
- Dodano Playwrightowy test `npm run test:ranking`, ktory renderuje UI i potwierdza kolejnosc: `Ignacy > Franek > Filip > Jozek > Lucja`.
- Backend przelicza passe z zatwierdzonych zadan `MIN`.
- Odczyt `points`, `streaks`, grant maps i `/api/leaderboard` uruchamia przeliczenie punktow/grantow z danych historycznych.
- Zablokowano cofanie/odrzucanie zatwierdzonego `completion` bez jawnej korekty punktow.
- Backend waliduje harmonogram zadania, aktywny dzien dziecka i daty dla `completion`.
- Backend waliduje date `extraTask`.
- `WEEKLY` dostal tygodniowy klucz naliczania punktow, wiec to samo zadanie tygodniowe nie powinno naliczac punktow codziennie.
- Aktywny dzien bez zadan `MIN` nie jest juz automatycznie `PASSED`, tylko `NO_REQUIRED_TASKS`.

## Weryfikacja Wykonana

- `node --check server.js` - OK.
- `node --check familyquest-app.compiled.js` - OK.
- `npm run test:ranking` - OK, Playwright sprawdzil realny DOM i zapisal screenshot do `tmp/ranking-order-check.png`.
- `npm test` z aktualnym `.env` nadal nie jest wiarygodne lokalnie, bo `DATABASE_URL` wskazuje baze Railway z niewaznymi danymi logowania.
- `DATABASE_URL='' npm test -- --runInBand` przechodzi, ale test suite jest wtedy pominiety, bo testy integracyjne wymagaja bazy.
- `npm run lint` nadal nie dziala, bo projekt nie ma konfiguracji ESLint.

## Najwazniejsze Otwarte Decyzje

### 1. Punktowy Ledger Zamiast Samego Salda

Status: czesciowo poprawione przez `recomputePointsAndGrants`, ale ledger nadal nie istnieje.

Obecnie saldo `data.points` jest przeliczane z:

- zatwierdzonych completion,
- punktow za zaliczone dni,
- bonusow tygodniowych,
- zatwierdzonych extra taskow,
- premii i kar z `pointAdjustments`.

To daje praktyczny mechanizm naprawczy, ale nie jest pelnym ledgerem. Nadal brakuje jawnej listy transakcji punktowych z powodami i mozliwoscia audytu.

Co zrobic dalej:

1. Dodac `pointLedger` do `FamilyState.data`.
2. Kazde naliczenie punktow zapisywac jako wpis ledgeru: `TASK_APPROVED`, `DAY_PASSED`, `WEEK_IDEAL`, `EXTRA_TASK`, `BONUS`, `PENALTY`, `MANUAL_CORRECTION`.
3. Ustalic, czy `data.points` jest cachem wyliczanym z ledgeru, czy autorytatywnym saldem walidowanym przeciw ledgerowi.
4. Dodac widok historii punktow dla rodzica i dziecka.

Priorytet: P1/P2.

### 2. Jawna Korekta Punktow Dla Cofania Zatwierdzen

Status: cofanie zatwierdzonego `completion` jest zablokowane.

To chroni saldo, ale rodzic nie ma jeszcze wygodnej sciezki "cofnij zatwierdzenie i skoryguj punkty". Na razie musi uzyc kary/premii recznej.

Co zrobic dalej:

1. Dodac osobna akcje rodzica: `void approval` albo `reverse approval`.
2. Pokazac rodzicowi przewidywany efekt punktowy.
3. Zapisac korekte jako `MANUAL_CORRECTION` lub przyszly wpis ledgeru.
4. Zdecydowac, co robic z nagrodami juz odblokowanymi przez punkty, ktore zostaly potem cofnięte.

Priorytet: P2.

### 3. Restore Backupu Osobno Od Storage Merge

Status: otwarte.

`/api/storage/merge` nadal jest synchronizacja klienta, nie pelnym restore. Backend ignoruje incoming `points` w zwyklym merge, co chroni przed starymi snapshotami, ale oznacza, ze import JSON w UI nie jest prawdziwym odtworzeniem backupu.

Co zrobic dalej:

1. Dodac endpoint `POST /api/storage/restore-backup`, tylko dla rodzica.
2. Walidowac caly snapshot przez `normalizeStateData`.
3. Nadpisywac stan jako restore, nie merge.
4. Po restore uruchomic `recomputePointsAndGrants`.
5. Frontendowy import JSON przepiac na ten endpoint.
6. Pokazac w UI komunikat, ze import zastapi dane rodziny.

Priorytet: P2.

### 4. Wersjonowanie `FamilyState`

Status: otwarte.

Stan rodziny nadal jest jednym JSON-em. Wiele endpointow robi wzorzec `loadStateData -> mutate -> saveStateData`. Rownolegle zapisy z dwoch urzadzen moga sie nadpisac.

Co zrobic dalej:

1. Dodac `version` do `FamilyState.data` albo osobne pole w modelu Prisma.
2. `saveStateData` powinno zapisywac warunkowo: aktualizuj tylko jesli wersja sie zgadza.
3. Przy konflikcie endpoint powinien ponowic operacje na swiezym stanie albo zwrocic `409`.
4. Najpierw objac tym operacje punktowe: approve/reject completion, extra task, point adjustment, restore backup.

Priorytet: P2.

### 5. Globalne Kolizje Kodow Dzieci

Status: otwarte.

Kody dzieci sa unikalne tylko w rodzinie, ale logowanie dziecka szuka kodu globalnie po wszystkich rodzinach. Dwie rodziny z tym samym kodem dziecka wywoluja konflikt.

Co zrobic dalej:

1. Dodac drugi skladnik logowania dziecka: kod rodziny + kod dziecka.
2. Alternatywnie generowac globalnie unikalne dluzsze kody.
3. Zmienic UI logowania dziecka i endpoint `/api/auth/login-child`.
4. Dodac test na dwie rodziny z tym samym kodem dziecka.

Priorytet: P2.

### 6. Semantyka Nagród Po Spadku Punktow

Status: otwarte/decyzja produktowa.

Nagrody raz odblokowane zostaja w `rewardUnlocks`, nawet gdy punkty spadna po karze albo rodzic zmieni progi nagrod. To moze byc dobre, jesli nagroda jest jednorazowym osiagnieciem, ale powinno byc jawne.

Co zrobic dalej:

1. Ustalic zasade: nagrody sa stale po odblokowaniu czy moga byc cofane.
2. Jesli stale, opisac to w UI rodzica.
3. Jesli cofane, dodac status `revoked` i logike ponownej oceny po karach/edycji progow.

Priorytet: P3/P2.

### 7. Zrodlo Frontendu I Build

Status: otwarte.

Uruchamiana aplikacja laduje `familyquest-app.compiled.js`. Plik `familyquest-app.jsx` wyglada na nieuzywany/stary. To jest ryzyko, bo latwo naprawic niewlasciwy plik.

Co zrobic dalej:

1. Ustalic jedno zrodlo prawdy.
2. Dodac skrypt build z JSX do compiled albo usunac/oznaczyc stary JSX jako legacy.
3. Zaktualizowac README.
4. Dopiero potem przenosic wieksze zmiany frontendowe.

Priorytet: P3, ale wazne operacyjnie.

### 8. Dokumentacja PWA I Service Worker

Status: otwarte.

`service-worker.js` usuwa cache i wyrejestrowuje SW. README nadal sugeruje PWA + Service Worker, co moze byc mylace.

Co zrobic dalej:

1. Zaktualizowac README: aplikacja ma manifest/install, ale bez offline cache.
2. Albo przywrocic kontrolowany cache z wersjonowaniem assetow.

Priorytet: P3.

### 9. Stabilne Testy Integracyjne

Status: otwarte.

Testy API wymagaja poprawnego `DATABASE_URL`. Obecny `.env` lokalnie wskazuje baze z niewaznymi danymi, wiec `npm test` pada na rejestracji.

Co zrobic dalej:

1. Dodac `.env.test.example`.
2. Opisac lokalna baze testowa w README.
3. Rozwazyc skrypt `test:db:setup`.
4. Dodac testy integracyjne dla:
   - blokady cofania zatwierdzonego completion,
   - walidacji harmonogramu i dat,
   - `WEEKLY` naliczanego raz na tydzien,
   - `NO_REQUIRED_TASKS`,
   - restore backup, gdy powstanie endpoint.

Priorytet: P2/P3.

## Kolejnosc Następnych Prac

Rekomendowana kolejność od teraz:

1. Dopisac integracyjne testy API dla juz naprawionych reguł, gdy bedzie dzialajacy testowy Postgres.
2. Dodac jawna akcje korekty/cofniecia zatwierdzenia z widocznym efektem punktowym.
3. Rozdzielic restore backup od zwyklego storage merge.
4. Dodac wersjonowanie `FamilyState` dla ochrony przed lost update.
5. Rozwiazac globalne kolizje kodow dzieci.
6. Uporzadkowac zrodlo frontendu i README/PWA.
7. Dopiero potem projektowac pelny `pointLedger`.

## Uwaga O Limicie I Zakresie

Przy niskim limicie tygodniowym nie warto robic wszystkich punktow naraz. Najbezpieczniejsze pakiety prac to:

- Pakiet A: testy regresyjne API dla obecnych napraw.
- Pakiet B: restore backup + UI importu.
- Pakiet C: wersjonowanie `FamilyState`.
- Pakiet D: logowanie dziecka z kodem rodziny.
- Pakiet E: porzadkowanie frontendu/build/docs.

