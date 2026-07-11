import React from 'react';

const formatShortDateTime = value => {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(0, 10);
  return date.toLocaleString('pl-PL', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};
const getRewardHistoryStatus = entry => {
  if (entry?.status === 'CLAIMED') return {
    className: 'claimed',
    label: 'Wydana',
    icon: '✅'
  };
  if (entry?.status === 'REVOKED') return {
    className: 'revoked',
    label: 'Cofnięta',
    icon: '↩️'
  };
  if (entry?.status === 'RESTORED') return {
    className: 'restored',
    label: 'Przywrócona',
    icon: '♻️'
  };
  return {
    className: 'available',
    label: 'Dostępna',
    icon: '🎁'
  };
};
const getRewardEventLabel = type => {
  if (type === 'UNLOCKED') return 'Odblokowana';
  if (type === 'REVOKED') return 'Cofnięta';
  if (type === 'RESTORED') return 'Przywrócona';
  if (type === 'CLAIMED') return 'Wydana';
  return 'Zdarzenie';
};
const RewardHistoryPanel = ({ history }) => React.createElement("div", {
  className: "glass-card reward-history-card",
  style: {
    marginTop: '1rem'
  }
}, React.createElement("div", {
  className: "reward-history-header"
}, React.createElement("div", null, React.createElement("h3", null, "Historia nagród"), React.createElement("p", null, "Pełny ślad odblokowań, cofnięć, przywróceń i wydań.")), React.createElement("div", {
  className: "reward-history-count"
}, history.length, " wpis\xF3w")), history.length === 0 ? React.createElement("div", {
  className: "empty-state"
}, "Brak historii nagr\xF3d") : React.createElement("div", {
  className: "reward-history-list"
}, history.map(entry => {
  const status = getRewardHistoryStatus(entry);
  return React.createElement("div", {
    key: entry.id,
    className: `reward-history-item ${status.className}`
  }, React.createElement("div", {
    className: "reward-history-status",
    "aria-label": status.label
  }, React.createElement("span", {
    className: "reward-history-status-icon"
  }, status.icon), React.createElement("span", null, status.label)), React.createElement("div", {
    className: "reward-history-main"
  }, React.createElement("div", {
    className: "reward-history-title-row"
  }, React.createElement("strong", null, entry.rewardTitle), React.createElement("span", null, entry.childName)), entry.rewardDescription && React.createElement("div", {
    className: "reward-history-description"
  }, entry.rewardDescription), React.createElement("div", {
    className: "reward-history-requirements"
  }, entry.requiredPoints ? React.createElement("span", {
    className: "badge badge-points"
  }, Number(entry.cycle || 1) > 1 ? `Próg ${entry.cycle}: ${entry.thresholdPoints || Number(entry.requiredPoints || 0) * Number(entry.cycle || 1)} pkt` : `${entry.requiredPoints} pkt`) : null, entry.requiredStreak ? React.createElement("span", {
    className: "badge badge-min"
  }, entry.requiredStreak, " dni passy") : null, entry.requiredIdealWeeks ? React.createElement("span", {
    className: "badge badge-weekly"
  }, entry.requiredIdealWeeks, " idealnych tyg.") : null), React.createElement("div", {
    className: "reward-history-timeline"
  }, (entry.events || []).map((event, index) => React.createElement("div", {
    key: `${entry.id}-${event.type}-${event.at}-${index}`,
    className: `reward-history-event ${String(event.type || '').toLowerCase()}`
  }, React.createElement("span", {
    className: "reward-history-event-dot"
  }), React.createElement("span", null, getRewardEventLabel(event.type)), React.createElement("time", null, formatShortDateTime(event.at)))))));
})));

export default RewardHistoryPanel;
