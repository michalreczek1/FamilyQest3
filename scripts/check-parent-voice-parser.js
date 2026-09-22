const assert = require("assert");
const fs = require("fs");
const path = require("path");

const entry = path.join(
  __dirname,
  "..",
  "src",
  "lib",
  "parentVoiceCommands.js",
);
const datesEntry = path.join(__dirname, "..", "src", "lib", "dates.js");
const datesUrl = `data:text/javascript;base64,${fs.readFileSync(datesEntry).toString("base64")}`;
const voiceSource = fs.readFileSync(entry, "utf8");
assert(voiceSource.includes("from './dates.js'"), "date module import changed");
const voiceUrl = `data:text/javascript;base64,${Buffer.from(voiceSource.replace("from './dates.js'", `from '${datesUrl}'`)).toString("base64")}`;

const run = async () => {
  const { parseParentVoiceCommand } = await import(voiceUrl);

  const names = [
    "Ignacy",
    "Franek",
    "Filip",
    "Jutka",
    "Józek",
    "Łucja",
    "Nela",
    "Blanka",
    "Agnieszka",
    "Kuba",
    "Zuzia",
    "Michał",
    "Ola",
    "Maja",
  ];
  const children = names.map((name, index) => ({ id: `child-${index}`, name }));
  const parse = (transcript, childId = null) =>
    parseParentVoiceCommand({
      transcript,
      children,
      childId,
      today: "2026-09-13",
    });

  for (const [spoken, expected] of [
    ["Ignacy", "Ignacy"],
    ["Ignacego", "Ignacy"],
    ["Ignacemu", "Ignacy"],
    ["Franka", "Franek"],
    ["Frankowi", "Franek"],
    ["Filipa", "Filip"],
    ["Filipowi", "Filip"],
    ["Jutka", "Jutka"],
    ["Jutki", "Jutka"],
    ["Józka", "Józek"],
    ["Józkowi", "Józek"],
    ["Juska", "Józek"],
    ["Jóskowi", "Józek"],
    ["Łucji", "Łucja"],
    ["Lucji", "Łucja"],
    ["Neli", "Nela"],
    ["Blance", "Blanka"],
    ["Agnieszce", "Agnieszka"],
    ["Kubie", "Kuba"],
    ["Zuzi", "Zuzia"],
    ["Michałowi", "Michał"],
    ["Oli", "Ola"],
    ["Mai", "Maja"],
  ]) {
    const result = parse(`dodaj dwa punkty ${spoken} za śniadanie`);
    assert.strictEqual(
      result.child?.name,
      expected,
      `${spoken}: ${JSON.stringify(result)}`,
    );
    assert.strictEqual(result.adjustmentType, "BONUS", spoken);
    assert.strictEqual(result.points, 2, spoken);
    const rewardResult = parse(`${spoken} wydano nagrodę`);
    assert.strictEqual(rewardResult.type, "ISSUE_REWARDS", spoken);
    assert.strictEqual(rewardResult.child?.name, expected, spoken);
    assert.strictEqual(rewardResult.count, 1, spoken);
  }

  const penalty = parse("dwa punkty kary dla Juska za niegrzeczne sniadanie");
  assert.strictEqual(penalty.child?.name, "Józek");
  assert.strictEqual(penalty.adjustmentType, "PENALTY");
  assert.strictEqual(penalty.points, 2);
  assert.strictEqual(
    penalty.note,
    "Odjęcie punktów za niegrzeczne sniadanie (dzisiaj)",
  );
  assert.strictEqual(
    parse("odejmij 2 punkty Filipowi za hałas").adjustmentType,
    "PENALTY",
  );
  assert.strictEqual(
    parse("dodaj 2 punkty Filipowi za pomoc").adjustmentType,
    "BONUS",
  );
  assert.strictEqual(
    parse("daj dwa punkty kary Józkowi za hałas").adjustmentType,
    "PENALTY",
  );

  const missing = parse("dodaj dwa punkty Dżemkowi za śniadanie");
  assert.strictEqual(missing.needsChildSelection, true);
  const chosen = parse(
    "dodaj dwa punkty Dżemkowi za śniadanie",
    children.find((child) => child.name === "Franek").id,
  );
  assert.strictEqual(chosen.child?.name, "Franek");
  const ambiguous = parse("dodaj dwa punkty Filipowi i Ignacemu za pomoc");
  assert.strictEqual(ambiguous.needsChildSelection, true);
  const dateName = parse("dodaj dwa punkty Filipowi za pomoc 12 maja");
  assert.strictEqual(dateName.child?.name, "Filip");
  assert.strictEqual(dateName.date, "2026-05-12");

  for (const [transcript, childName] of [
    ["zatwierdź wszystkie zadania Franka", "Franek"],
    ["zatwierdź wszystkie zadania Filipa", "Filip"],
  ]) {
    const result = parse(transcript);
    assert.strictEqual(result.type, "APPROVE_PENDING", transcript);
    assert.strictEqual(result.child?.name, childName, transcript);
  }
  for (const [transcript, childName, count] of [
    ["Ignacemu wydano dwie nagrody", "Ignacy", 2],
    ["Ignacemu wydano nagrodę", "Ignacy", 1],
    ["Frankowi wydano nagrodę", "Franek", 1],
  ]) {
    const result = parse(transcript);
    assert.strictEqual(result.type, "ISSUE_REWARDS", transcript);
    assert.strictEqual(result.child?.name, childName, transcript);
    assert.strictEqual(result.count, count, transcript);
  }

  console.log(
    `Parent voice parser OK: ${names.length} children, inflections, phonetic Józek variants, bonus, penalty and safe manual selection`,
  );
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
