export const getLeaderboardPoints = value => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
};
export const sortChildrenForLeaderboard = (children, streaks, points) => [...children].sort((a, b) => {
  const aPoints = getLeaderboardPoints(points[a.id]);
  const bPoints = getLeaderboardPoints(points[b.id]);
  if (aPoints !== bPoints) return bPoints - aPoints;
  const aStreak = streaks[a.id]?.current || 0;
  const bStreak = streaks[b.id]?.current || 0;
  if (aStreak !== bStreak) return bStreak - aStreak;
  const aIdeal = streaks[a.id]?.idealWeeksInRow || 0;
  const bIdeal = streaks[b.id]?.idealWeeksInRow || 0;
  if (aIdeal !== bIdeal) return bIdeal - aIdeal;
  return String(a.name || '').localeCompare(String(b.name || ''), 'pl');
});
export const rankIcon = index => {
  if (index === 0) return '🏆';
  if (index === 1) return '🥈';
  if (index === 2) return '🥉';
  return `${index + 1}.`;
};
