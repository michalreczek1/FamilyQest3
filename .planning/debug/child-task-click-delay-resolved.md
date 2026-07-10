# Debug: child-task-click-delay

## Status

Resolved and verified.

## Root cause

Commit `360cc18` moved task persistence to `POST /api/completions`, but removed the immediate local state transition. The UI then waited for both the API response and a full family snapshot reload before showing the pending state.

## Fix

- Apply an optimistic completion immediately after the click.
- Persist through the dedicated completion endpoint.
- Reconcile the optimistic record with the server response without reloading the full snapshot.
- Track mutation versions per child/task/date so an older queued response cannot overwrite a newer click.
- Roll back only the current mutation when persistence fails.

## Verification

- Focused delayed-response Playwright: pending state appeared in 55 ms.
- Jest: passed.
- Child login Playwright: passed.
- Approval queue Playwright: passed.
- Full API suite: 14/14 passed.
- Smoke test on isolated PostgreSQL test database: passed.
- Frontend production build: passed.
