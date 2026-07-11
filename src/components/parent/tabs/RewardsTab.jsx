import React from 'react';

const RewardsTab = ({
  children,
  rewards,
  rewardUnlocks,
  activeRewards,
  setShowModal,
  setEditingReward,
  archiveReward,
  claimReward,
}) => {
  return React.createElement(React.Fragment, null, React.createElement("div", {
      className: "header"
    }, React.createElement("h2", null, "Katalog nagr\xF3d"), React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => setShowModal('addReward')
    }, "+ Dodaj nagrod\u0119")), activeRewards.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, React.createElement("div", {
      style: {
        fontSize: '3rem'
      }
    }, "\uD83C\uDF81"), React.createElement("p", null, "Brak nagr\xF3d. Dodaj pierwsz\u0105 nagrod\u0119!")) : activeRewards.map(reward => React.createElement("div", {
      key: reward.id,
      className: "task-item"
    }, React.createElement("div", {
      style: {
        fontSize: '2rem'
      }
    }, "\uD83C\uDF81"), React.createElement("div", {
      style: {
        flex: 1
      }
    }, React.createElement("div", {
      style: {
        fontWeight: 600
      }
    }, reward.title), React.createElement("div", {
      style: {
        fontSize: '0.9rem',
        opacity: 0.7
      }
    }, reward.description), React.createElement("div", {
      style: {
        marginTop: '0.5rem',
        display: 'flex',
        gap: '0.5rem'
      }
    }, reward.requiredPoints && React.createElement("div", {
      className: "badge badge-points"
    }, reward.requiredPoints, " pkt • każdy pełny próg"), reward.requiredStreak && React.createElement("div", {
      className: "badge badge-min"
    }, reward.requiredStreak, " dni passy"), reward.requiredIdealWeeks && React.createElement("div", {
      className: "badge badge-weekly"
    }, reward.requiredIdealWeeks, " idealnych tygodni"))), React.createElement("button", {
      className: "btn btn-secondary",
      onClick: () => setEditingReward(reward)
    }, "\u270F\uFE0F Edytuj"), React.createElement("button", {
      className: "btn btn-danger",
      onClick: () => {
        if (confirm(`Zarchiwizować nagrodę "${reward.title}"? Dzieci zachowają już odblokowane nagrody.`)) {
          archiveReward(reward.id);
        }
      }
    }, "\uD83D\uDDC3\uFE0F Usu\u0144"))), React.createElement("div", {
      className: "glass-card",
      style: {
        marginTop: '1rem'
      }
    }, React.createElement("h3", {
      style: {
        marginBottom: '0.75rem'
      }
    }, "Odblokowane nagrody"), rewardUnlocks.filter(unlock => !unlock.revokedAt).length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, "Brak odblokowanych nagr\xF3d") : rewardUnlocks.filter(unlock => !unlock.revokedAt).map(unlock => {
      const reward = rewards.find(r => r.id === unlock.rewardId);
      const child = children.find(c => c.id === unlock.childId);
      if (!reward || !child) return null;
      return React.createElement("div", {
        key: unlock.id,
        className: "task-item"
      }, React.createElement("div", {
        style: {
          fontSize: '2rem'
        }
      }, "\uD83C\uDFC5"), React.createElement("div", {
        style: {
          flex: 1
        }
      }, React.createElement("div", {
        style: {
          fontWeight: 600
        }
      }, reward.title), Number(unlock.cycle || 1) > 1 && Number(reward.requiredPoints || 0) > 0 && React.createElement("div", {
        style: {
          fontSize: '0.8rem',
          opacity: 0.72,
          marginTop: '0.2rem'
        }
      }, "Próg ", unlock.cycle, " (", Number(reward.requiredPoints || 0) * Number(unlock.cycle || 1), " pkt)"), React.createElement("div", {
        style: {
          fontSize: '0.85rem',
          opacity: 0.8
        }
      }, child.name, " \u2022 odblokowano: ", unlock.unlockedAt?.slice(0, 10)), React.createElement("div", {
        style: {
          fontSize: '0.8rem',
          opacity: 0.7
        }
      }, unlock.claimedAt ? `Wydano: ${unlock.claimedAt.slice(0, 10)}` : 'Oczekuje na wydanie')), !unlock.claimedAt && React.createElement("button", {
        className: "btn btn-success",
        onClick: () => claimReward(unlock.id)
      }, "\u2705 Wydano"));
    })));
};

export default RewardsTab;
