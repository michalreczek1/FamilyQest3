# ADR 0001: Stabilna synchronizacja rodziny

## Status

Zaakceptowane

## Kontekst

Frontend odświeżał dane rodziny w wielu niezależnych żądaniach. Odpowiedzi mogły
dotyczyć różnych wersji stanu, a starsza odpowiedź mogła nadpisać nowszy widok
lub przywrócić widok po lokalnym wylogowaniu.

## Decyzje

- Stan sesji klienta ma `authState` (`active` albo `loggedOut`) i rosnące
  `sessionGeneration`. Wynik żądania może zmienić widok tylko w tej samej
  generacji sesji.
- Backend zwraca nie-sekretny `sessionRef` (JWT `jti`) wyłącznie do korelacji
  sesji. Nie jest on poświadczeniem i jest maskowany w telemetrii.
- Lokalny wpis odwołania sesji jest powiązany z `sessionRef` i ma stany
  `pending`, `confirmed` oraz `expired`. Nie blokuje świadomego logowania.
- `GET /api/family-state` zwraca pojedynczy, filtrowany snapshot rodziny:
  `familyId`, `version`, `generatedAt`, `viewer`, `permissions` i `family`.
  Endpoint nie ma skutków ubocznych.
- `version` opisuje agregat `FamilyState`; `ETag` opisuje reprezentację HTTP
  konkretnego odbiorcy. Wersje porównujemy tylko w tym samym kontekście
  `sessionGeneration + familyId + representationScope`.
- Klient ma dwa tryby synchronizacji: `refresh()` deduplikuje identyczne
  żądania, a `forceRefresh()` unieważnia poprzednie i stosuje zasadę
  latest-wins.
- Mutacje używają nagłówka `Idempotency-Key`. Rekord idempotencji jest
  jednoznaczny dla `userId + familyId + operationCode + idempotencyKey`;
  `requestHash` jest walidacją, nie częścią klucza.
- Dla krótkich mutacji konkurencyjne żądanie może czekać tylko w ograniczonym
  czasie. Po jego przekroczeniu API zwraca `409 IDEMPOTENCY_RESULT_PENDING`
  oraz `Retry-After`; klient zachowuje ten sam klucz i nie zakłada porażki.
- Retry serwerowy dotyczy wyłącznie przejściowych błędów serializacji. Retry
  klienta po konflikcie jest klasyfikowany per operacja jako `automaticRetry`,
  `refreshAndConfirm` albo `neverRetryAutomatically`.

## Konsekwencje

- Odczyty `GET` nie zapisują punktów, nagród ani stanu rodziny.
- Frontend przestaje budować widok z wielu `/api/storage/get/*`.
- Timeout lub anulowanie oczekiwania nie oznacza anulowania mutacji po stronie
  serwera; wynik jest rozstrzygany tym samym kluczem idempotencji.
- SSE/WebSocket mogą później wyłącznie sygnalizować nową wersję i wywołać
  odświeżenie. Nie zastępują snapshotów ani kontroli wersji.
