const fs = require('fs');
const path = require('path');
const { prisma, __test } = require('../server');

const clone = (value) => JSON.parse(JSON.stringify(value || {}));
const getTime = (item) => Date.parse(item?.occurredAt || item?.approvedAt || item?.createdAt || item?.updatedAt || 0) || 0;
const sortLedgerDesc = (a, b) => {
  const timeDiff = getTime(b) - getTime(a);
  if (timeDiff !== 0) return timeDiff;
  return String(b.id || b.sourceId || '').localeCompare(String(a.id || a.sourceId || ''), 'pl');
};
const completionKey = (completion) => `${completion.childId}|${completion.taskId}|${completion.date}`;

const formatLedger = (entries) =>
  entries
    .slice()
    .sort(sortLedgerDesc)
    .slice(0, 20)
    .map((entry) => ({
      type: entry.type,
      title: entry.title,
      delta: entry.delta,
      previousPoints: entry.previousPoints,
      newPoints: entry.newPoints,
      date: entry.date,
      occurredAt: entry.occurredAt,
      sourceId: entry.sourceId,
      affectsBalance: entry.affectsBalance,
    }));

(async () => {
  const states = await prisma.familyState.findMany({ include: { family: true } });
  const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  const outDir = path.join(process.cwd(), '.deploy-backups', `point-forensics-${timestamp}`);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'family-states.json'), JSON.stringify(states, null, 2));

  const report = states.map((state) => {
    const data = clone(state.data);
    const recomputed = clone(state.data);
    __test.recomputePointsAndGrants(recomputed);

    const children = Array.isArray(data.children) ? data.children : [];
    const tasks = Array.isArray(data.tasks) ? data.tasks : [];
    const completions = Array.isArray(data.completions) ? data.completions : [];
    const tasksById = new Map(tasks.map((task) => [task.id, task]));
    const childrenById = new Map(children.map((child) => [child.id, child]));
    const duplicateMap = new Map();

    completions
      .filter((completion) => completion.approvedByParent)
      .forEach((completion) => {
        const key = completionKey(completion);
        if (!duplicateMap.has(key)) duplicateMap.set(key, []);
        duplicateMap.get(key).push(completion);
      });

    const duplicateGroups = [...duplicateMap.entries()]
      .filter(([, items]) => items.length > 1)
      .map(([key, items]) => {
        const [childId, taskId, date] = key.split('|');
        return {
          child: childrenById.get(childId)?.name || childId,
          childId,
          task: tasksById.get(taskId)?.title || taskId,
          taskId,
          date,
          count: items.length,
          ids: items.map((item) => item.id),
          approvedAt: items.map((item) => item.approvedAt || item.updatedAt || item.createdAt || null),
        };
      })
      .sort((a, b) => String(a.child).localeCompare(String(b.child), 'pl') || String(a.date).localeCompare(String(b.date)));

    const childSummaries = children.map((child) => {
      const storedPoints = Number(data.points?.[child.id] || 0);
      const recomputedPoints = Number(recomputed.points?.[child.id] || 0);
      const storedLedger = (Array.isArray(data.pointLedger) ? data.pointLedger : []).filter((entry) => entry.childId === child.id);
      const recomputedLedger = (Array.isArray(recomputed.pointLedger) ? recomputed.pointLedger : []).filter(
        (entry) => entry.childId === child.id,
      );
      const approvedOn16 = completions
        .filter((completion) => completion.childId === child.id && completion.date === '2026-05-16' && completion.approvedByParent)
        .map((completion) => ({
          id: completion.id,
          task: tasksById.get(completion.taskId)?.title || completion.taskId,
          taskId: completion.taskId,
          approvedAt: completion.approvedAt,
          updatedAt: completion.updatedAt,
        }))
        .sort((a, b) => String(a.task).localeCompare(String(b.task), 'pl'));

      return {
        child: child.name,
        childId: child.id,
        storedPoints,
        recomputedPoints,
        deltaStoredMinusRecomputed: storedPoints - recomputedPoints,
        storedLedgerBalance: storedLedger.length ? storedLedger.slice().sort(sortLedgerDesc)[0]?.newPoints : null,
        recomputedLedgerBalance: recomputedLedger.length
          ? recomputedLedger.slice().sort(sortLedgerDesc)[0]?.newPoints
          : null,
        approvedOn2026_05_16: approvedOn16,
        duplicateApprovedGroups: duplicateGroups.filter((group) => group.childId === child.id),
        latestStoredLedger: formatLedger(storedLedger),
        latestRecomputedLedger: formatLedger(recomputedLedger),
      };
    });

    return {
      family: state.family?.name || state.familyId,
      familyId: state.familyId,
      stateId: state.id,
      version: state.version,
      backupDir: outDir,
      duplicateGroups,
      childSummaries,
    };
  });

  fs.writeFileSync(path.join(outDir, 'point-report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  await prisma.$disconnect();
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  process.exit(1);
});
