import { toDateString } from './dates.js';

const NUMBER_WORDS = { zero: 0, jeden: 1, jedna: 1, jedno: 1, jednego: 1, dwa: 2, dwie: 2, dwoch: 2, dwoma: 2, trzy: 3, trzech: 3, cztery: 4, czterech: 4, piec: 5, szesc: 6, siedem: 7, osiem: 8, dziewiec: 9, dziesiec: 10 };
const MONTHS = { stycznia: 0, lutego: 1, marca: 2, kwietnia: 3, maja: 4, czerwca: 5, lipca: 6, sierpnia: 7, wrzesnia: 8, pazdziernika: 9, listopada: 10, grudnia: 11 };

export const normalizeVoiceText = (value) => String(value || '').toLocaleLowerCase('pl-PL').replace(/ł/g, 'l').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();
const normalizeVoiceSound = (value) => String(value || '').toLocaleLowerCase('pl-PL').replace(/ó/g, 'u').replace(/rz/g, 'z').replace(/[żź]/g, 'z').replace(/ł/g, 'l').normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/z(?=k)/g, 's').replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();

const validDate = (year, month, day) => {
  const date = new Date(year, month, day, 12);
  return date.getFullYear() === year && date.getMonth() === month && date.getDate() === day;
};

const requestedDate = (transcript, normalized, today) => {
  const raw = String(transcript || '');
  const iso = raw.match(/\b(20\d{2})[-./](\d{1,2})[-./](\d{1,2})\b/);
  const dotted = raw.match(/\b(\d{1,2})\.(\d{1,2})\.(20\d{2})\b/);
  const parsed = iso ? [Number(iso[1]), Number(iso[2]) - 1, Number(iso[3])] : dotted ? [Number(dotted[3]), Number(dotted[2]) - 1, Number(dotted[1])] : null;
  if (parsed && validDate(...parsed)) return { date: toDateString(new Date(...parsed, 12)), explicit: true };
  const named = normalized.match(/\b(\d{1,2})\s+(stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|wrzesnia|pazdziernika|listopada|grudnia)(?:\s+(20\d{2}))?\b/);
  if (named) {
    const todayDate = new Date(`${today}T12:00:00`);
    const parts = [Number(named[3] || todayDate.getFullYear()), MONTHS[named[2]], Number(named[1])];
    if (validDate(...parts)) return { date: toDateString(new Date(...parts, 12)), explicit: true };
  }
  const offset = /\bprzedwczoraj\b/.test(normalized) ? -2 : /\bwczoraj\b/.test(normalized) ? -1 : 0;
  if (offset) {
    const date = new Date(`${today}T12:00:00`);
    date.setDate(date.getDate() + offset);
    return { date: toDateString(date), explicit: true };
  }
  return { date: today, explicit: /\b(dzis|dzisiaj)\b/.test(normalized) };
};

const nameForms = (name) => {
  const base = String(name || '').toLocaleLowerCase('pl-PL');
  const forms = new Set([base]);
  if (base.endsWith('a')) {
    const root = base.slice(0, -1);
    if (root.length >= 2) {
      [root, `${root}i`, `${root}y`, `${root}ie`, `${root}e`, `${root}o`].forEach((form) => forms.add(form));
      if (root.endsWith('k')) forms.add(`${root.slice(0, -1)}ce`);
      if (root.endsWith('g')) forms.add(`${root.slice(0, -1)}dze`);
      if (root.endsWith('t')) forms.add(`${root.slice(0, -1)}cie`);
      if (root.endsWith('d')) forms.add(`${root}zie`);
    }
    if (base.endsWith('aja')) forms.add(`${base.slice(0, -2)}i`); // Maja → Mai
  } else if (base.endsWith('y')) {
    const root = base.slice(0, -1);
    [`${root}ego`, `${root}emu`, `${root}ym`].forEach((form) => forms.add(form));
  } else {
    [`${base}a`, `${base}owi`, `${base}em`, `${base}u`].forEach((form) => forms.add(form));
    if (base.endsWith('ek')) {
      const root = base.slice(0, -2);
      [`${root}ka`, `${root}kowi`, `${root}kiem`].forEach((form) => forms.add(form));
    }
  }
  return new Set([...forms].flatMap((form) => [normalizeVoiceText(form), normalizeVoiceSound(form)]));
};

const matchChildren = (transcript, children) => {
  const withoutDate = (value) => value.replace(/\b\d{1,2}\s+(stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|wrzesnia|pazdziernika|listopada|grudnia)(?:\s+20\d{2})?\b/g, ' ');
  const tokens = [normalizeVoiceText(transcript), normalizeVoiceSound(transcript)].flatMap((value) => withoutDate(value).split(' ').filter(Boolean));
  return children.filter((child) => String(child.name || '').split(/\s+/).filter(Boolean).every((name) => {
    const forms = nameForms(name);
    return tokens.some((token) => forms.has(token));
  }));
};

const getPoints = (normalized) => {
  const tokens = normalized.split(' ');
  const index = tokens.findIndex((token) => token.startsWith('punkt'));
  if (index < 1) return null;
  const token = tokens[index - 1];
  if (/^\d{1,4}$/.test(token)) return Number(token);
  if (Object.prototype.hasOwnProperty.call(NUMBER_WORDS, token)) return NUMBER_WORDS[token];
  return null;
};

const adjustmentNote = ({ transcript, child, date, today, type }) => {
  const names = String(child.name || '').split(/\s+/).filter(Boolean).map(nameForms);
  const words = String(transcript || '').trim().split(/\s+/).filter(Boolean);
  const afterZa = words.findIndex((word) => normalizeVoiceText(word) === 'za');
  const reason = (afterZa < 0 ? [] : words.slice(afterZa + 1)).filter((word) => {
    const token = normalizeVoiceText(word);
    return token && !token.startsWith('punkt') && !names.some((forms) => forms.has(token) || forms.has(normalizeVoiceSound(word))) && !['dzis', 'dzisiaj', 'wczoraj', 'przedwczoraj'].includes(token) && !/^\d{1,2}(?:\.\d{1,2})?(?:\.20\d{2})?$/.test(token);
  }).join(' ').replace(/\s+/g, ' ').trim();
  const dateLabel = date === today ? 'dzisiaj' : date;
  if (!reason) return `${type === 'PENALTY' ? 'Kara' : 'Premia'} przyznana głosowo (${dateLabel})`;
  return `${type === 'PENALTY' ? 'Odjęcie punktów za' : 'Za'} ${reason} (${dateLabel})`;
};

const taskQuery = (normalized, child) => {
  let result = normalized
    .replace(/\b\d{1,2}\s+(stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|wrzesnia|pazdziernika|listopada|grudnia)(?:\s+20\d{2})?\b/g, ' ')
    .replace(/\b20\d{2}\s+\d{1,2}\s+\d{1,2}\b/g, ' ')
    .replace(/\b(zalicz|oznacz|wykonaj|zadanie|dla|dziecku|dziecka|dzis|dzisiaj|wczoraj|przedwczoraj)\b/g, ' ');
  const forms = String(child.name || '').split(/\s+/).filter(Boolean).map(nameForms);
  result = result.split(' ').filter((token) => !forms.some((aliases) => aliases.has(token) || aliases.has(normalizeVoiceSound(token)))).join(' ');
  return result.replace(/\s+/g, ' ').trim();
};

export const parseParentVoiceCommand = ({ transcript, children = [], today = toDateString(new Date()), childId = null }) => {
  const normalized = normalizeVoiceText(transcript);
  if (!normalized) return { error: 'Powiedz polecenie, a ja przygotuję jego potwierdzenie.' };
  const activeChildren = children.filter((item) => !item.archived);
  const matches = childId ? activeChildren.filter((item) => item.id === childId) : matchChildren(transcript, activeChildren);
  if (matches.length !== 1) return activeChildren.length ? { error: 'Nie rozpoznałem jednoznacznie dziecka. Wybierz je z listy i przygotuj polecenie ponownie.', needsChildSelection: true } : { error: 'Brak dzieci, dla których można wykonać polecenie.' };
  const child = matches[0];
  const { date, explicit } = requestedDate(transcript, normalized, today);
  const points = getPoints(normalized);
  const isPenalty = /\b(odejmij|odejm|zabierz|potrac|ukaraj|ukarz|kara|kary|karne|minus)\b/.test(normalized) && /\bpunkt/.test(normalized);
  const isBonus = /\b(dodaj|przyznaj|daj|premia|premie|bonus)\b/.test(normalized) && /\bpunkt/.test(normalized);
  const text = String(transcript || '').trim();
  if (isBonus || isPenalty) {
    if (!Number.isInteger(points) || points < 1 || points > 1000) return { error: 'Podaj liczbę punktów od 1 do 1000.' };
    const adjustmentType = isPenalty ? 'PENALTY' : 'BONUS';
    return { type: 'POINT_ADJUSTMENT', child, points, adjustmentType, date, transcript: text, note: adjustmentNote({ transcript, child, date, today, type: adjustmentType }) };
  }
  const extra = /\b(dodatkow|extra)\b/.test(normalized);
  const reject = /\b(odrzuc|nie zatwierdzaj)\b/.test(normalized);
  const approve = /\b(zatwierdz|zaakceptuj|akceptuj)\b/.test(normalized);
  if (approve || reject) {
    if (extra && approve && (!Number.isInteger(points) || points < 0 || points > 1000)) return { error: 'Przy zadaniu dodatkowym podaj liczbę punktów, np. „zatwierdź zadania dodatkowe Mai za 2 punkty”.' };
    return { type: extra ? (reject ? 'REJECT_EXTRA_TASKS' : 'APPROVE_EXTRA_TASKS') : (reject ? 'REJECT_PENDING' : 'APPROVE_PENDING'), child, points: extra && approve ? points : null, date: explicit ? date : null, transcript: text };
  }
  if (/\b(zalicz|oznacz|wykonaj)\b/.test(normalized)) return { type: 'COMPLETE_TASK', child, date, taskQuery: taskQuery(normalized, child), transcript: text };
  return { error: 'Obsługuję premie i kary punktowe, zatwierdzanie lub odrzucanie zadań, zadania dodatkowe oraz zaliczanie zadania.' };
};
