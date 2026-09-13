import { toDateString } from './dates.js';

const NUMBER_WORDS = { zero: 0, jeden: 1, jedna: 1, jedno: 1, dwa: 2, dwie: 2, trzy: 3, cztery: 4, piec: 5, szesc: 6, siedem: 7, osiem: 8, dziewiec: 9, dziesiec: 10 };
const MONTHS = { stycznia: 0, lutego: 1, marca: 2, kwietnia: 3, maja: 4, czerwca: 5, lipca: 6, sierpnia: 7, wrzesnia: 8, pazdziernika: 9, listopada: 10, grudnia: 11 };

export const normalizeVoiceText = (value) => String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('pl-PL').replace(/[^a-z0-9\s]/g, ' ').replace(/\s+/g, ' ').trim();

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

const matchChild = (normalized, children) => {
  const tokens = normalized.split(' ').filter(Boolean);
  const matches = children.filter((child) => normalizeVoiceText(child.name).split(' ').filter(Boolean).every((name) => {
    const stem = name.slice(0, Math.min(5, name.length));
    return tokens.some((token) => token === name || (stem.length >= 4 && token.startsWith(stem)));
  }));
  return matches.length === 1 ? matches[0] : null;
};

const getPoints = (normalized) => {
  const tokens = normalized.split(' ');
  const index = tokens.findIndex((token) => token.startsWith('punkt'));
  const candidates = index < 0 ? tokens : tokens.slice(Math.max(0, index - 5), index);
  for (let current = candidates.length - 1; current >= 0; current -= 1) {
    const token = candidates[current];
    if (/^\d{1,4}$/.test(token)) return Number(token);
    if (Object.prototype.hasOwnProperty.call(NUMBER_WORDS, token)) return NUMBER_WORDS[token];
  }
  return null;
};

const adjustmentNote = ({ transcript, child, date, today, type }) => {
  const stems = normalizeVoiceText(child.name).split(' ').map((name) => name.slice(0, Math.min(5, name.length)));
  const words = String(transcript || '').trim().split(/\s+/).filter(Boolean);
  const afterZa = words.findIndex((word) => normalizeVoiceText(word) === 'za');
  const reason = (afterZa < 0 ? [] : words.slice(afterZa + 1)).filter((word) => {
    const token = normalizeVoiceText(word);
    return token && !token.startsWith('punkt') && !stems.some((stem) => stem && token.startsWith(stem)) && !['dzis', 'dzisiaj', 'wczoraj', 'przedwczoraj'].includes(token) && !/^\d{1,2}(?:\.\d{1,2})?(?:\.20\d{2})?$/.test(token);
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
  normalizeVoiceText(child.name).split(' ').forEach((name) => {
    const stem = name.slice(0, Math.min(5, name.length));
    result = result.replace(new RegExp(`\\b${stem}[a-z]*\\b`, 'g'), ' ');
  });
  return result.replace(/\s+/g, ' ').trim();
};

export const parseParentVoiceCommand = ({ transcript, children = [], today = toDateString(new Date()) }) => {
  const normalized = normalizeVoiceText(transcript);
  if (!normalized) return { error: 'Powiedz polecenie, a ja przygotuję jego potwierdzenie.' };
  const child = matchChild(normalized, children.filter((item) => !item.archived));
  if (!child) return { error: 'Nie rozpoznałem dziecka z aktualnej listy. Wymień jego imię.' };
  const { date, explicit } = requestedDate(transcript, normalized, today);
  const points = getPoints(normalized);
  const isPenalty = /\b(odejmij|zabierz|ukaraj|kara)\b/.test(normalized) && /\bpunkt/.test(normalized);
  const isBonus = /\b(dodaj|przyznaj|daj)\b/.test(normalized) && /\bpunkt/.test(normalized);
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
