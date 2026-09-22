import React from 'react';

const RewardsTab = ({ children, rewards, rewardUnlocks, activeRewards, setShowModal, setEditingReward, archiveReward, claimReward }) => {
  const available = rewardUnlocks.filter(unlock => !unlock.revokedAt && !unlock.claimedAt);
  const issued = rewardUnlocks.filter(unlock => !unlock.revokedAt && unlock.claimedAt);

  const renderUnlock = (unlock, isPending) => {
    const reward = rewards.find(item => item.id === unlock.rewardId);
    const child = children.find(item => item.id === unlock.childId);
    if (!reward || !child) return null;
    return React.createElement('div', { key: unlock.id, className: 'task-item' },
      React.createElement('div', { style: { fontSize: '2rem' } }, isPending ? '🎁' : '🏅'),
      React.createElement('div', { style: { flex: 1 } },
        React.createElement('div', { style: { fontWeight: 600 } }, reward.title),
        Number(unlock.cycle || 1) > 1 && Number(reward.requiredPoints || 0) > 0 && React.createElement('div', { style: { fontSize: '0.8rem', opacity: 0.72 } }, `Próg ${unlock.cycle} (${Number(reward.requiredPoints) * Number(unlock.cycle)} pkt)`),
        React.createElement('div', { style: { fontSize: '0.85rem', opacity: 0.8 } }, `${child.name} • zdobyto: ${unlock.unlockedAt?.slice(0, 10) || '—'}`),
        !isPending && React.createElement('div', { style: { fontSize: '0.8rem', opacity: 0.7 } }, `Wydano: ${unlock.claimedAt?.slice(0, 10)}`)),
      isPending ? React.createElement('button', { type: 'button', className: 'btn btn-primary', onClick: () => claimReward(unlock.id) }, 'Wydaj nagrodę') : React.createElement('span', { className: 'badge badge-min' }, 'Wydana'));
  };

  return React.createElement(React.Fragment, null,
    React.createElement('div', { className: 'header' }, React.createElement('h2', null, 'Nagrody'), React.createElement('button', { className: 'btn btn-primary', onClick: () => setShowModal('addReward') }, '+ Dodaj nagrodę')),
    React.createElement('section', { className: 'glass-card reward-queue' },
      React.createElement('h3', null, `Do wydania (${available.length})`),
      available.length ? available.map(unlock => renderUnlock(unlock, true)) : React.createElement('div', { className: 'empty-state' }, 'Nie ma nagród do wydania.')),
    React.createElement('section', { className: 'glass-card reward-queue' },
      React.createElement('h3', null, `Wydane (${issued.length})`),
      issued.length ? issued.map(unlock => renderUnlock(unlock, false)) : React.createElement('div', { className: 'empty-state' }, 'Nie wydano jeszcze żadnej nagrody.')),
    React.createElement('section', { className: 'reward-catalog' },
      React.createElement('h3', null, 'Katalog nagród'),
      activeRewards.length === 0 ? React.createElement('div', { className: 'empty-state' }, 'Brak nagród. Dodaj pierwszą nagrodę!') : activeRewards.map(reward => React.createElement('div', { key: reward.id, className: 'task-item' },
        React.createElement('div', { style: { fontSize: '2rem' } }, '🎁'),
        React.createElement('div', { style: { flex: 1 } },
          React.createElement('div', { style: { fontWeight: 600 } }, reward.title),
          React.createElement('div', { style: { fontSize: '0.9rem', opacity: 0.7 } }, reward.description),
          React.createElement('div', { style: { marginTop: '0.5rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' } },
            reward.requiredPoints && React.createElement('span', { className: 'badge badge-points' }, `${reward.requiredPoints} pkt • każdy pełny próg`),
            reward.requiredStreak && React.createElement('span', { className: 'badge badge-min' }, `${reward.requiredStreak} dni passy`),
            reward.requiredIdealWeeks && React.createElement('span', { className: 'badge badge-weekly' }, `${reward.requiredIdealWeeks} idealnych tygodni`))),
        React.createElement('button', { className: 'btn btn-secondary', onClick: () => setEditingReward(reward) }, '✏️ Edytuj'),
        React.createElement('button', { className: 'btn btn-danger', onClick: () => { if (confirm(`Zarchiwizować nagrodę "${reward.title}"? Dzieci zachowają już odblokowane nagrody.`)) archiveReward(reward.id); } }, '🗃️ Usuń')))));
};

export default RewardsTab;
