const assert = require('assert');
const { __test, prisma } = require('../server');

const createFakeFamilyStateClient = () => {
  const records = new Map([
    [
      'state-1',
      {
        id: 'state-1',
        familyId: 'family-1',
        version: 7,
        data: { children: [] },
      },
    ],
  ]);

  const client = {
    async update({ where, data }) {
      const record = records.get(where.id);
      if (!record) throw new Error('not found');
      record.data = data.data;
      record.version += Number(data.version?.increment || 0);
      return { ...record };
    },
    async updateMany({ where, data }) {
      const record = records.get(where.id);
      if (!record || record.version !== where.version) {
        return { count: 0 };
      }
      record.data = data.data;
      record.version += Number(data.version?.increment || 0);
      return { count: 1 };
    },
    async findUnique({ where }) {
      const record = records.get(where.id);
      return record ? { ...record } : null;
    },
  };

  return { client, records };
};

(async () => {
  const { client, records } = createFakeFamilyStateClient();
  const saveStateData = __test.createSaveStateData(client);
  const loadedA = { id: 'state-1', version: 7 };
  const loadedB = { id: 'state-1', version: 7 };

  const afterA = await saveStateData(loadedA, { children: [{ id: 'a' }] });
  assert.strictEqual(afterA.version, 8, 'first write should increment version');

  let conflict = null;
  try {
    await saveStateData(loadedB, { children: [{ id: 'b' }] });
  } catch (error) {
    conflict = error;
  }
  assert(conflict, 'second stale write should throw');
  assert(__test.isFamilyStateConflict(conflict), 'stale write should be FamilyState conflict');

  const skipped = await saveStateData(loadedB, { children: [{ id: 'b' }] }, { skipOnConflict: true });
  assert.strictEqual(skipped, null, 'skipOnConflict should return null on stale version');

  records.set('state-2', {
    id: 'state-2',
    familyId: 'family-1',
    version: 4,
    data: {
      children: [{ id: 'a', name: 'Ania' }],
      tasks: [],
      completions: [],
      points: { a: 1 },
      streaks: { a: { current: 1 } },
      auditLogs: [],
    },
  });
  const loadedCompatible = { id: 'state-2', version: 4 };
  const compatibleData = {
    children: [{ id: 'a', name: 'Ania' }],
    tasks: [{ id: 'task-1', childId: 'a', title: 'Test' }],
    completions: [],
    points: { a: 1 },
    streaks: { a: { current: 1 } },
    auditLogs: [],
  };
  __test.attachStateDataConflictBase(loadedCompatible, records.get('state-2').data);
  records.get('state-2').version = 5;
  records.get('state-2').data = {
    ...records.get('state-2').data,
    points: { a: 2 },
    streaks: { a: { current: 2 } },
    auditLogs: [{ id: 'audit-1', createdAt: new Date().toISOString() }],
  };
  const afterCompatibleRetry = await saveStateData(loadedCompatible, compatibleData);
  assert.strictEqual(afterCompatibleRetry.version, 6, 'compatible computed-only conflict should retry');
  assert.deepStrictEqual(
    afterCompatibleRetry.data.tasks,
    [{ id: 'task-1', childId: 'a', title: 'Test' }],
    'compatible retry should persist the intended write',
  );

  await prisma.$disconnect();
  console.log('FamilyState versioning OK: stale conflicts are blocked, compatible computed conflicts retry');
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  process.exit(1);
});
