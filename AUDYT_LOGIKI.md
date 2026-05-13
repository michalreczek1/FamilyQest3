# Audyt logiki aplikacji FamilyQuest

Data audytu: 2026-05-09  
Ostatnia aktualizacja: 2026-05-13

Zakres: backend `server.js`, uruchamiany frontend `familyquest-app.compiled.js`, `index.html`, `prisma/schema.prisma`, testy integracyjne, smoke, Playwrightowy test rankingu i wdrozenie na Proxmox.

## Status Po Ostatnich Zmianach

Naprawiony i wdrozony zostal krytyczny pakiet logiki punktow i rankingu:

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
- Produkcja `https://fq.familyos.pl` zostala zaktualizowana do `c5a0a81`.
- CSP na produkcji zawiera `script-src 'self' 'unsafe-inline' https://unpkg.com`, wiec frontend nie powinien zatrzymywac sie na ekranie `Ladowanie FamilyQuest...` z powodu blokady inline script.
- Dodano jawne cofniecie zatwierdzenia zadania przez rodzica: `POST /api/completions/:id/reverse-approval`.
- Cofniecie zatwierdzenia przelicza punkty i passe ze zrodel prawdy, zapisuje jawny wpis `REVERSAL` w `pointAdjustments` i nie nalicza tej korekty drugi raz przy kolejnym `recomputePointsAndGrants`.
- Panel rodzica pokazuje przycisk `Cofnij` przy zatwierdzonym zadaniu na wybrany dzien i wyswietla realny efekt punktowy po operacji.
- Dodano osobny restore backupu: `POST /api/storage/restore-backup`, dostepny tylko dla rodzica.
- Import JSON w UI uzywa teraz restore, a nie lokalnej podmiany stanu i pozniejszego `storage/merge`.
- Restore backupu normalizuje snapshot, nadpisuje stan rodziny, przelicza punkty/passę na serwerze i dopisuje audit log `RESTORE_BACKUP`.

## Weryfikacja Wykonana

- `node --check server.js` - OK.
- `node --check familyquest-app.compiled.js` - OK.
- `npm run test:ranking` - OK, Playwright sprawdzil realny DOM i zapisal screenshot do `tmp/ranking-order-check.png`.
- `RANKING_BASE_URL=https://fq.familyos.pl npm run test:ranking` - OK po wdrozeniu, Playwright sprawdzil publicznie serwowany HTML/JS z kontrolowanymi danymi API.
- `https://fq.familyos.pl/health` - OK, backend i baza odpowiadaja.
- Snapshot przed wdrozeniem: `predeploy-familyquest-20260513-105625`.
- Backup plikow produkcyjnych przed pull: `/opt/familyquest/.deploy-backups/local-before-pull-20260513-105626`.
- `npm run test:reverse-approval` - OK, test sprawdzil logike cofniecia `9 -> 4` punktow bez podwojnego odejmowania po recompute oraz UI rodzica z przyciskiem `Cofnij` i alertem `-5 pkt`.
- `npm run test:restore-backup` - OK, test sprawdzil przeliczenie punktow ze snapshotu `999 -> 7`, zastapienie danych rodziny i brak uzycia `storage/merge` podczas importu.
- `npm test` z aktualnym `.env` nadal nie jest wiarygodne lokalnie, bo `DATABASE_URL` wskazuje baze Railway z niewaznymi danymi logowania.
- `DATABASE_URL='' npm test -- --runInBand` przechodzi, ale test suite jest wtedy pominiety, bo testy integracyjne wymagaja bazy.
- `npm run lint` nadal nie dziala, bo projekt nie ma konfiguracji ESLint.

## Co Nadal Jest Do Zrobienia

Po wdrozeniu rankingu i passy nie ma juz otwartego krytycznego bledu w samym porzadku tablicy wynikow. Zostaly ryzyka drugiego poziomu:

1. Brak pelnego ledgeru punktow, czyli historii transakcji punktowych.
2. Brak ochrony przed rownoleglym nadpisaniem `FamilyState`.
3. Kody dzieci moga kolidowac globalnie miedzy rodzinami.
4. Testy API wymagaja stabilnej lokalnej bazy testowej.
5. Frontend nadal ma nieuporzadkowane zrodlo prawdy: uruchamiany jest `familyquest-app.compiled.js`, a `familyquest-app.jsx` wyglada na legacy.

## Rekomendowany Nastepny Pakiet

Najbardziej sensowny kolejny pakiet po restore backupu: **wersjonowanie `FamilyState` / ochrona przed lost update**.

Dlaczego ten pakiet teraz:

- Coraz wiecej operacji krytycznych robi `loadStateData -> mutate -> saveStateData`.
- Restore, cofniecie zatwierdzenia, approve i premie/kary moga sie nadpisywac, jesli dwa urzadzenia zapisza stan rownolegle.
- Po rozdzieleniu restore od merge to jest teraz najwieksze pozostale ryzyko integralnosci danych.
- Da sie wdrozyc etapami: najpierw wersja w JSON i retry na wybranych endpointach punktowych, potem pole Prisma.

Minimalny zakres wdrozenia:

1. Dodac `version` do `FamilyState.data`.
2. `loadStateData` ma zwracac wersje, a `saveStateData` zapisywac tylko gdy wersja sie zgadza.
3. Przy konflikcie endpoint powinien ponowic operacje na swiezym stanie albo zwrocic `409`.
4. Najpierw objac endpointy: approve/reject/reverse completion, extra task approve/reject, point adjustment, restore backup.
5. Dodac test symulujacy dwa rownolegle zapisy, z potwierdzeniem ze drugi nie nadpisuje cicho pierwszego.

Ryzyko/decyzja przed implementacja:

- Wariant z wersja tylko w JSON jest szybszy, ale mniej atomowy niz osobne pole Prisma. Rekomendacja: jesli chcemy realnie zamknac lost update, dodac osobne pole `version` w modelu `FamilyState`.

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

Status: wdrozone.

Rodzic ma osobna sciezke `reverse-approval`. Completion jest oznaczany jako odrzucony po cofnieciu, punkty i passa sa przeliczane, a wpis `REVERSAL` trafia do `pointAdjustments` jako jawna historia efektu.

Co zostaje dalej:

1. Rozbudowac to pozniej o pelny ledger punktow.
2. Zdecydowac, co robic z nagrodami juz odblokowanymi przez punkty, ktore zostaly potem cofniete.
3. Dodac docelowy test integracyjny na prawdziwej bazie, gdy bedzie stabilny `DATABASE_URL` testowy.

Priorytet: zrealizowane, pozostale decyzje P2/P3.

### 3. Restore Backupu Osobno Od Storage Merge

Status: wdrozone.

`/api/storage/merge` zostaje synchronizacja klienta, a import JSON uzywa osobnego `POST /api/storage/restore-backup`. Restore nadpisuje caly stan rodziny, normalizuje dane i uruchamia `recomputePointsAndGrants`, wiec snapshotowe `points` nie sa autorytatywne.

Co zostaje dalej:

1. Rozwazyc dodatkowy PIN dla restore po wdrozeniu wersjonowania.
2. Dodac docelowy test integracyjny na prawdziwej bazie.

Priorytet: zrealizowane, pozostale decyzje P3.

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

1. Dodac wersjonowanie `FamilyState` dla ochrony przed lost update.
2. Rozwiazac globalne kolizje kodow dzieci.
3. Uporzadkowac zrodlo frontendu i README/PWA.
4. Dopiero potem projektowac pelny `pointLedger`.

## Uwaga O Limicie I Zakresie

Przy niskim limicie tygodniowym nie warto robic wszystkich punktow naraz. Najbezpieczniejsze pakiety prac to:

- Pakiet A: wersjonowanie `FamilyState`.
- Pakiet B: logowanie dziecka z kodem rodziny.
- Pakiet C: porzadkowanie frontendu/build/docs.
- Pakiet D: pelny ledger punktow.
