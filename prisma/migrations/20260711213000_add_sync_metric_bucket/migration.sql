CREATE TABLE "SyncMetricBucket" (
    "id" TEXT NOT NULL,
    "bucketStart" TIMESTAMP(3) NOT NULL,
    "metric" TEXT NOT NULL,
    "cohort" TEXT NOT NULL,
    "count" BIGINT NOT NULL DEFAULT 0,
    "total" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SyncMetricBucket_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "SyncMetricBucket_bucketStart_metric_cohort_key" ON "SyncMetricBucket"("bucketStart", "metric", "cohort");
CREATE INDEX "SyncMetricBucket_bucketStart_idx" ON "SyncMetricBucket"("bucketStart");
