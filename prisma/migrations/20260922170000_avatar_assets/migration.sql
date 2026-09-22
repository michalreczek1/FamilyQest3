CREATE TABLE "AvatarAsset" (
    "id" TEXT NOT NULL,
    "familyId" TEXT NOT NULL,
    "contentType" TEXT NOT NULL,
    "bytes" BYTEA NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AvatarAsset_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "AvatarAsset_familyId_idx" ON "AvatarAsset"("familyId");

ALTER TABLE "AvatarAsset" ADD CONSTRAINT "AvatarAsset_familyId_fkey"
FOREIGN KEY ("familyId") REFERENCES "Family"("id") ON DELETE CASCADE ON UPDATE CASCADE;
