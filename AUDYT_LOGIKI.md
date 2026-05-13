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
- Dodano wersjonowanie `FamilyState` jako osobne pole Prisma `version`.
- `saveStateData` zapisuje warunkowo po `id + version` i podbija wersje po kazdym udanym zapisie.
- Staly zapis ze starej wersji zwraca konflikt `FAMILY_STATE_VERSION_CONFLICT` zamiast cicho nadpisac nowsze dane.
- Dodano `pointLedger` do stanu rodziny jako serwerowy cache historii punktow.
- `recomputePointsAndGrants` generuje ledger z zatwierdzonych zadan, zaliczonych dni, idealnych tygodni, extra taskow oraz premii/kar/cofniec.
- Saldo `points` jest teraz cachem wynikajacym z tych samych wpisow zrodlowych co ledger, a nie osobna prawda biznesowa.
- Dziecko moze kliknac liczbe punktow i zobaczyc przewijalny popup `Historia punktow` z deltami, opisem, data i saldem po operacji.

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
- `npm run test:state-version` - OK, test zasymulowal dwa rownolegle zapisy i potwierdzil konflikt przy drugim zapisie ze stara wersja.
- `npx prisma validate` - OK, schema z `FamilyState.version` jest poprawna.
- `npm run test:point-ledger` - OK, test sprawdzil wpisy ledgeru `TASK_APPROVED`, `DAY_PASSED`, `EXTRA_TASK`, `BONUS` oraz popup historii punktow dziecka.
- `npm test` z aktualnym `.env` nadal nie jest wiarygodne lokalnie, bo `DATABASE_URL` wskazuje baze Railway z niewaznymi danymi logowania.
- `DATABASE_URL='' npm test -- --runInBand` przechodzi, ale test suite jest wtedy pominiety, bo testy integracyjne wymagaja bazy.
- `npm run lint` nadal nie dziala, bo projekt nie ma konfiguracji ESLint.

## Co Nadal Jest Do Zrobienia

Po wdrozeniu rankingu i passy nie ma juz otwartego krytycznego bledu w samym porzadku tablicy wynikow. Zostaly ryzyka drugiego poziomu:

1. Kody dzieci moga kolidowac globalnie miedzy rodzinami.
2. Testy API wymagaja stabilnej lokalnej bazy testowej.
3. Frontend nadal ma nieuporzadkowane zrodlo prawdy: uruchamiany jest `familyquest-app.compiled.js`, a `familyquest-app.jsx` wyglada na legacy.

## Rekomendowany Nastepny Pakiet

Najbardziej sensowny kolejny pakiet po wersjonowaniu: **globalne kolizje kodow dzieci**.

Dlaczego ten pakiet teraz:

- Logowanie dziecka nadal szuka `accessCode` globalnie po wszystkich rodzinach.
- Dwie rodziny z tym samym kodem dziecka moga dostac konflikt przy logowaniu.
- To jest mniejsze i bardziej domkniete niz pelny ledger punktow.
- Da sie zweryfikowac testem fixture: dwie rodziny, ten sam kod dziecka, logowanie przez kod rodziny + kod dziecka.

Minimalny zakres wdrozenia:

1. Dodac rodzinny kod logowania albo jawny identyfikator rodziny dla dziecka.
2. Zmienic UI logowania dziecka: kod rodziny + kod dziecka.
3. Zmienic `/api/auth/login-child`, zeby najpierw zawęzal rodzine, a dopiero potem szukal dziecka.
4. Zachowac migracyjnie stary tryb tylko wtedy, gdy kod dziecka jest globalnie unikalny.
5. Dodac test na dwie rodziny z tym samym kodem dziecka.

Ryzyko/decyzja przed implementacja:

- Trzeba wybrac format kodu rodziny. Rekomendacja: krotki, czytelny kod 4-6 znakow przypisany rodzinie, a nie email rodzica w logowaniu dziecka.

## Najwazniejsze Otwarte Decyzje

### 1. Punktowy Ledger Zamiast Samego Salda

Status: wdrozone w wersji serwerowego ledgeru wyliczanego ze zrodel prawdy.

Obecnie saldo `data.points` jest przeliczane z:

- zatwierdzonych completion,
- punktow za zaliczone dni,
- bonusow tygodniowych,
- zatwierdzonych extra taskow,
- premii i kar z `pointAdjustments`.

To daje praktyczny ledger audytowy. `data.points` pozostaje cachem do szybkiego wyswietlania, ale jest przeliczany razem z `pointLedger`.

Co zostaje dalej:

1. Dodac opcjonalny widok historii punktow w panelu rodzica.
2. Po uporzadkowaniu frontendu przeniesc popup historii punktow do komponentu z prawdziwego zrodla JSX.
3. Jesli kiedys powstanie osobna tabela ledgeru, migrowac `pointLedger` z JSON-a do DB.

Priorytet: zrealizowane, rozszerzenia P3.

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

Status: wdrozone.

Stan rodziny nadal jest jednym JSON-em, ale `FamilyState` ma teraz pole `version`, a `saveStateData` robi warunkowy zapis po oczekiwanej wersji. Rownolegly zapis ze stara wersja dostaje konflikt zamiast cichego nadpisania.

Co zostaje dalej:

1. Rozwazyc retry dla wybranych idempotentnych operacji.
2. Dodac docelowy test integracyjny na prawdziwej bazie, gdy lokalny `DATABASE_URL` bedzie stabilny.

Priorytet: zrealizowane, retry/test DB P3.

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

1. Rozwiazac globalne kolizje kodow dzieci.
2. Uporzadkowac zrodlo frontendu i README/PWA.
3. Uporzadkowac/rozszerzyc widoki historii punktow dla rodzica po porzadkowaniu frontendu.

## Uwaga O Limicie I Zakresie

Przy niskim limicie tygodniowym nie warto robic wszystkich punktow naraz. Najbezpieczniejsze pakiety prac to:

- Pakiet A: logowanie dziecka z kodem rodziny.
- Pakiet B: porzadkowanie frontendu/build/docs.
- Pakiet C: rozszerzony widok ledgeru dla rodzica.
