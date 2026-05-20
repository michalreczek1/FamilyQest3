const fs = require('fs');
const path = require('path');
require('./test-env');
const { prisma, __test } = require('../server');

const clone = (value) => JSON.parse(JSON.stringify(value || {}));
const shouldApply = process.argv.includes('--apply');

const fingerprintComputed = (data) =>
  JSON.stringify({
    points: data.points || {},
    streaks: data.streaks || {},
    pointLedger: data.pointLedger || [],
    taskPointGrants: data.taskPointGrants || {},
    dayPointGrants: data.dayPointGrants || {},
    weekBonusGrants: data.weekBonusGrants || {},
  });

(async () => {
  const states = await prisma.familyState.findMany({ include: { family: true } });
  const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const outDir = path.join(process.cwd(), '.deploy-backups', `recompute-family-state-${timestamp}`);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'before.json'), JSON.stringify(states, null, 2));

  const results = [];
  for (const state of states) {
    const beforeData = clone(state.data);
    const afterData = clone(state.data);
    const beforeFingerprint = fingerprintComputed(beforeData);
    __test.recomputePointsAndGrants(afterData);
    const afterFingerprint = fingerprintComputed(afterData);
    const changed = beforeFingerprint !== afterFingerprint;
    const childResults = (afterData.children || []).map((child) => {
      const latestLedger = (afterData.pointLedger || []).find((entry) => entry.childId === child.id) || null;
      return {
        child: child.name,
        childId: child.id,
        beforePoints: Number(beforeData.points?.[child.id] || 0),
        afterPoints: Number(afterData.points?.[child.id] || 0),
        latestLedgerNewPoints: latestLedger?.newPoints ?? null,
      };
    });

    if (changed && shouldApply) {
      await prisma.familyState.update({
        where: { id: state.id },
        data: {
          data: afterData,
          version: { increment: 1 },
        },
      });
    }

    results.push({
      family: state.family?.name || state.familyId,
      familyId: state.familyId,
      stateId: state.id,
      changed,
      applied: changed && shouldApply,
      childResults,
    });
  }

  fs.writeFileSync(path.join(outDir, shouldApply ? 'applied-report.json' : 'dry-run-report.json'), JSON.stringify(results, null, 2));
  console.log(JSON.stringify({ mode: shouldApply ? 'apply' : 'dry-run', backupDir: outDir, results }, null, 2));
  await prisma.$disconnect();
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  process.exit(1);
});
