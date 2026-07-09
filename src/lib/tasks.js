import { getDayNumber, toDateString } from './dates.js';

export const TASK_TEMPLATES = [{
  id: 'tpl-bed',
  title: 'Pościel łóżko',
  tier: 'MIN',
  points: 2,
  description: 'Rano po wstaniu'
}, {
  id: 'tpl-teeth',
  title: 'Umyj zęby',
  tier: 'MIN',
  points: 1,
  description: 'Rano i wieczorem'
}, {
  id: 'tpl-homework',
  title: 'Odrób lekcje',
  tier: 'MIN',
  points: 4,
  description: 'Po szkole'
}, {
  id: 'tpl-room',
  title: 'Posprzątaj pokój',
  tier: 'PLUS',
  points: 5,
  description: '15 minut porządków'
}, {
  id: 'tpl-reading',
  title: 'Czytanie 20 minut',
  tier: 'PLUS',
  points: 4,
  description: 'Dowolna książka'
}, {
  id: 'tpl-weekly-sport',
  title: 'Trening tygodniowy',
  tier: 'WEEKLY',
  points: 12,
  description: 'Min. 1 trening'
}];
export const isValidChildAccessCode = value => /^\d{4}$/.test(String(value || ''));
export const findAvailableChildAccessCode = (children, preferredCode = null, excludeChildId = null) => {
  const used = new Set((children || []).filter(c => c.id !== excludeChildId && isValidChildAccessCode(c.accessCode)).map(c => c.accessCode));
  if (isValidChildAccessCode(preferredCode) && !used.has(preferredCode)) return preferredCode;
  for (let i = 0; i <= 9999; i++) {
    const code = String(i).padStart(4, '0');
    if (!used.has(code)) return code;
  }
  return null;
};
export const isTaskScheduledForDate = (task, dateInput) => {
  if (!Array.isArray(task?.daysOfWeek) || task.daysOfWeek.length === 0) return true;
  return task.daysOfWeek.includes(getDayNumber(dateInput));
};
export const isTaskActiveForDate = (task, dateInput) => {
  if (!task) return false;
  const date = toDateString(dateInput);
  const createdDate = task.createdAt ? toDateString(task.createdAt) : null;
  if (createdDate && date < createdDate) return false;

  const archivedDate = task.archivedAt || (task.active === false ? task.updatedAt : null);
  if (!archivedDate) return task.active !== false;
  if (date < toDateString(archivedDate)) return true;

  return Boolean(task.active !== false && task.restoredAt && date >= toDateString(task.restoredAt));
};
export const normalizeTaskArchiveText = value => String(value || '').trim().replace(/\s+/g, ' ').toLocaleLowerCase('pl');
export const normalizeTaskArchiveDays = days => Array.isArray(days) ? [...new Set(days.map(day => Number(day)).filter(day => Number.isInteger(day) && day >= 1 && day <= 7))].sort((a, b) => a - b) : [];
export const getTaskArchiveFingerprint = task => JSON.stringify({
  title: normalizeTaskArchiveText(task?.title),
  tier: task?.tier || '',
  points: Number(task?.points || 0),
  description: normalizeTaskArchiveText(task?.description),
  daysOfWeek: normalizeTaskArchiveDays(task?.daysOfWeek)
});
