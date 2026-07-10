CREATE TABLE "IdempotencyOperation" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "familyId" TEXT NOT NULL,
    "operationCode" TEXT NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "requestHash" TEXT NOT NULL,
    "responseStatus" INTEGER,
    "responseBody" JSONB,
    "completedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IdempotencyOperation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "IdempotencyOperation_userId_familyId_operationCode_idempotencyKey_key"
ON "IdempotencyOperation"("userId", "familyId", "operationCode", "idempotencyKey");

CREATE INDEX "IdempotencyOperation_expiresAt_idx" ON "IdempotencyOperation"("expiresAt");
