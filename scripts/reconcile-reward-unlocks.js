const fs = require('fs');
const path = require('path');
require('dotenv').config();

const { prisma, __test } = require('../server');

const shouldApply = process.argv.includes('--apply');
const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
const outputDir = path.join(process.cwd(), '.deploy-backups', `reconcile-reward-unlocks-${timestamp}`);

const getSummary = (data) => {
  const unlocks = Array.isArray(data?.rewardUnlocks) ? data.rewardUnlocks : [];
  return {
    unlockCount: unlocks.length,
    activeUnlockCount: unlocks.filter((unlock) => !unlock.revokedAt).length,
    cyclicUnlockCount: unlocks.filter((unlock) => Number(unlock.cycle || 1) > 1).length,
  };
};

const reconcileState = async (stateId) => {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const result = await prisma.$transaction(async (tx) => {
      const state = await tx.familyState.findUnique({ where: { id: stateId } });
      if (!state) return { missing: true };

      const data = __test.normalizeStateData(state.data);
      const before = getSummary(data);
      const changed = __test.reconcileRewardUnlocksForAllChildren(data, null);
      const after = getSummary(data);

      if (!changed) return { changed: false, familyId: state.familyId, before, after };
      if (!shouldApply) return { changed: true, familyId: state.familyId, before, after, applied: false };

      const updated = await tx.familyState.updateMany({
        where: { id: state.id, version: state.version },
        data: { data, version: { increment: 1 } },
      });
      if (updated.count !== 1) return { conflict: true };

      return { changed: true, familyId: state.familyId, before, after, applied: true };
    });

    if (!result?.conflict) return result;
  }
  throw new Error(`Nie udało się bezpiecznie uzgodnić nagród dla FamilyState ${stateId}`);
};

(async () => {
  const states = await prisma.familyState.findMany({ select: { id: true, familyId: true, data: true } });
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, 'before.json'), JSON.stringify(states, null, 2));

  const results = [];
  for (const state of states) {
    results.push(await reconcileState(state.id));
  }

  const report = {
    mode: shouldApply ? 'apply' : 'dry-run',
    backupDir: outputDir,
    statesScanned: states.length,
    statesChanged: results.filter((result) => result?.changed).length,
    cyclicUnlocksAdded: results.reduce(
      (total, result) => total + Math.max(0, Number(result?.after?.cyclicUnlockCount || 0) - Number(result?.before?.cyclicUnlockCount || 0)),
      0,
    ),
    results,
  };
  fs.writeFileSync(path.join(outputDir, shouldApply ? 'applied-report.json' : 'dry-run-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
})()
  .catch((error) => {
    console.error('Reward unlock reconciliation failed:', error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
