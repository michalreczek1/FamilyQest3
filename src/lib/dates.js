export const parseDateInput = dateInput => {
  if (typeof dateInput === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dateInput)) {
    const [year, month, day] = dateInput.split('-').map(Number);
    return new Date(year, month - 1, day);
  }
  return new Date(dateInput);
};
export const toDateString = (dateInput = new Date()) => {
  const date = parseDateInput(dateInput);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
};
export const getDayNumber = dateInput => {
  const day = parseDateInput(dateInput).getDay();
  return day === 0 ? 7 : day;
};
export const getWeekStart = dateInput => {
  const date = parseDateInput(dateInput);
  const day = date.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  date.setDate(date.getDate() + diff);
  return toDateString(date);
};
