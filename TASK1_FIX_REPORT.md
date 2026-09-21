# Task 1 transactional proof-consumption fix report

## Scope

Task 1's account-verification implementation already used PostgreSQL conditional updates for
attempts and proof claims. This fix completes the transactional boundary without changing the
public service interface or unrelated Task 1 behavior.

## Root cause

The conditional proof claim was committed before the subsequent account mutation. A later
account-write failure could therefore consume a proof permanently even though its email change,
confirmation, or password replacement did not commit. The relational attempt increments also
needed an explicit transaction around their conditional updates.

## Fix

- PostgreSQL attempt failures issue `UPDATE ... WHERE Id AND ConsumedAt IS NULL AND Attempts <
  MaxAttempts`, incrementing in the database and failing closed when no row is eligible.
- Relational email confirmation, email change, and password-reset paths start a transaction before
  conditionally consuming the proof, then commit only after the account mutation succeeds.
- Password reset validates policy before claiming the proof and revokes sibling pending proofs with
  a database update inside the same transaction.
- The EF in-memory provider keeps its narrowly scoped fallback because it supports neither
  relational transactions nor database bulk updates; PostgreSQL is the production-concurrency
  authority.

## Regression coverage

- Deterministic PostgreSQL concurrent invalid-password-reset attempts: all consumers read the same
  proof snapshot, while the stored attempt count remains capped at `MaxAttempts`.
- Deterministic PostgreSQL concurrent valid-password-reset consumption: exactly one account password
  mutation commits and the losing consumer receives an invalid/expired proof result.
- PostgreSQL rollback fixtures directly seed proofs so they verify that a failed email-change or
  password-reset mutation leaves its proof retryable.

## Verification

- `dotnet test tests/PandaAuth.Tests/PandaAuth.Tests.csproj --filter
  'FullyQualifiedName~AccountVerificationServiceTests' --no-restore`: 17 passed.
- `PANDA_AUTH_TEST_POSTGRES=<local dedicated PostgreSQL 18 connection> dotnet test
  tests/PandaAuth.Tests/PandaAuth.Tests.csproj --filter
  'FullyQualifiedName~UserStoreMigrationTests' --no-restore`: 10 passed.

No full regression was run; it was outside the bounded request.
