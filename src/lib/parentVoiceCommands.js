import { toDateString } from './dates.js';

const NUMBER_WORDS = {
  zero: 0,
  jeden: 1,
  jedna: 1,
  jedno: 1,
  dwa: 2,
  dwie: 2,
  trzy: 3,
  cztery: 4,
  piec: 5,
  szesc: 6,
  siedem: 7,
  osiem: 8,
  dziewiec: 9,
  dziesiec: 10,
};

export const normalizeVoiceText = (value) => String(value || '')
  .normalize('NFD')
  .replace(/[\u0300-\u036f]/g, '')
  .toLocaleLowerCase('pl-PL')
  .replace(/[^a-z0-9\s]/g, ' ')
  .replace(/\s+/g, ' ')
  .trim();

const getRelativeDate = (normalizedText, today) => {
  if (/\bwczoraj\b/.test(normalizedText)) {
    const yesterday = new Date(`${today}T12:00:00`);
    yesterday.setDate(yesterday.getDate() - 1);
    return toDateString(yesterday);
  }
  return today;
};

const getChildMatch = (normalizedText, children) => {
  const tokens = normalizedText.split(' ').filter(Boolean);
  const matches = children.filter((child) => {
    const name = normalizeVoiceText(child.name);
    if (!name) return false;
    const stem = name.slice(0, Math.min(5, name.length));
    return tokens.some((token) => token === name || (stem.length >= 4 && token.startsWith(stem)));
  });
  return matches.length === 1 ? matches[0] : null;
};

const getPoints = (normalizedText) => {
  const tokens = normalizedText.split(' ');
  const pointIndex = tokens.findIndex((token) => token.startsWith('punkt'));
  const candidates = pointIndex === -1 ? tokens : tokens.slice(Math.max(0, pointIndex - 4), pointIndex);
  for (let index = candidates.length - 1; index >= 0; index -= 1) {
    const token = candidates[index];
    if (/^\d{1,4}$/.test(token)) return Number(token);
    if (Object.prototype.hasOwnProperty.call(NUMBER_WORDS, token)) return NUMBER_WORDS[token];
  }
  return null;
};

const getBonusNote = ({ transcript, child, date, today }) => {
  const childStem = normalizeVoiceText(child.name).slice(0, Math.min(5, normalizeVoiceText(child.name).length));
  const words = String(transcript || '').trim().split(/\s+/).filter(Boolean);
  const afterZa = words.findIndex((word) => normalizeVoiceText(word) === 'za');
  const reasonWords = afterZa === -1 ? [] : words.slice(afterZa + 1).filter((word) => {
    const token = normalizeVoiceText(word);
    return token &&
      !token.startsWith('punkt') &&
      !token.startsWith(childStem) &&
      token !== 'dzis' &&
      token !== 'dzisiaj' &&
      token !== 'wczoraj';
  });
  const reason = reasonWords.join(' ').replace(/\s+/g, ' ').trim();
  const dateLabel = date === today ? 'dzisiaj' : 'wczoraj';
  return reason ? `Za ${reason} (${dateLabel})` : `Premia przyznana głosowo (${dateLabel})`;
};

export const parseParentVoiceCommand = ({ transcript, children = [], today = toDateString(new Date()) }) => {
  const normalizedText = normalizeVoiceText(transcript);
  if (!normalizedText) return { error: 'Powiedz polecenie, a ja przygotuję jego potwierdzenie.' };

  const child = getChildMatch(normalizedText, children.filter((item) => !item.archived));
  if (!child) {
    return { error: 'Nie rozpoznałem dziecka. Wymień imię, np. „Filipowi” albo „Ignacemu”.' };
  }

  const date = getRelativeDate(normalizedText, today);
  const isApproval = /\b(zatwierdz|zalicz|zaakceptuj|akceptuj)/.test(normalizedText);
  if (isApproval) {
    return {
      type: 'APPROVE_PENDING',
      child,
      date: /\b(dzis|dzisiaj|wczoraj)\b/.test(normalizedText) ? date : null,
      transcript: String(transcript || '').trim(),
    };
  }

  const isBonus = /\b(dodaj|przyznaj|daj)\b/.test(normalizedText) && /\bpunkt/.test(normalizedText);
  if (isBonus) {
    const points = getPoints(normalizedText);
    if (!Number.isInteger(points) || points < 1 || points > 1000) {
      return { error: 'Podaj liczbę punktów od 1 do 1000, np. „dodaj dwa punkty Filipowi”.' };
    }
    return {
      type: 'BONUS_POINTS',
      child,
      points,
      date,
      note: getBonusNote({ transcript, child, date, today }),
      transcript: String(transcript || '').trim(),
    };
  }

  return {
    error: 'Rozumiem zatwierdzanie zadań oraz dodawanie punktów. Spróbuj np. „zatwierdź zadania Filipa” lub „dodaj dwa punkty Ignacemu za zmywarkę wczoraj”.',
  };
};
