import React from 'react';

const ChildrenTab = ({
  activeChildren,
  tasks,
  streaks,
  points,
  setShowModal,
  setEditingChild,
  archiveChild,
  addPointAdjustment,
  childAccessCodes = {},
}) => {
  return React.createElement(React.Fragment, null, React.createElement("div", {
      className: "header"
    }, React.createElement("h2", null, "Zarz\u0105dzanie dzie\u0107mi"), React.createElement("button", {
      className: "btn btn-primary",
      onClick: () => setShowModal('addChild')
    }, "+ Dodaj dziecko")), activeChildren.length === 0 ? React.createElement("div", {
      className: "empty-state"
    }, React.createElement("div", {
      style: {
        fontSize: '3rem'
      }
    }, "\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67\u200D\uD83D\uDC66"), React.createElement("p", null, "Brak dzieci. Dodaj pierwsze dziecko!")) : React.createElement("div", {
      className: "grid grid-2"
    }, activeChildren.map(child => {
      const childStreak = streaks[child.id] || {
        current: 0,
        best: 0
      };
      const childPoints = points[child.id] || 0;
      const childTasks = tasks.filter(t => t.childId === child.id);
      const visibleAccessCode = childAccessCodes[child.id];
      return React.createElement("div", {
        key: child.id,
        className: "glass-card"
      }, React.createElement("div", {
        className: "child-avatar"
      }, child.avatar), React.createElement("h3", {
        style: {
          textAlign: 'center',
          marginBottom: '1rem'
        }
      }, child.name), React.createElement("div", {
        className: "grid grid-2",
        style: {
          marginBottom: '1rem'
        }
      }, React.createElement("div", {
        className: "stat-card"
      }, React.createElement("div", {
        className: "stat-value"
      }, childPoints), React.createElement("div", {
        className: "stat-label"
      }, "punkt\xF3w")), React.createElement("div", {
        className: "stat-card"
      }, React.createElement("div", {
        className: "stat-value"
      }, childStreak.current), React.createElement("div", {
        className: "stat-label"
      }, "passa"))), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7,
          textAlign: 'center'
        }
      }, childTasks.length, " zada\u0144 \u2022 Dni aktywne: ", child.activeDays.join(', ')), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.85,
          textAlign: 'center',
          marginTop: '0.35rem'
        }
      }, visibleAccessCode ? React.createElement(React.Fragment, null, "Nowy kod dziecka: ", React.createElement("strong", null, visibleAccessCode)) : "Kod dziecka: ukryty. Ustaw nowy kod w edycji, jeśli trzeba."), React.createElement("div", {
        className: "child-admin-actions"
      }, React.createElement("button", {
        className: "btn btn-secondary",
        onClick: () => setEditingChild(child)
      }, "\u270F\uFE0F Edytuj"), React.createElement("button", {
        className: "btn btn-danger",
        onClick: () => {
          if (confirm(`Archiwizować profil ${child.name}?`)) {
            archiveChild(child.id);
          }
        }
      }, "\uD83D\uDDC3\uFE0F Archiwizuj")), React.createElement("div", {
        className: "child-admin-actions"
      }, React.createElement("button", {
        className: "btn btn-success",
        onClick: () => addPointAdjustment(child, 'BONUS')
      }, "\uD83C\uDF81 Premia"), React.createElement("button", {
        className: "btn btn-danger",
        onClick: () => addPointAdjustment(child, 'PENALTY')
      }, "\u26A0\uFE0F Kara")));
    })));
};

export default ChildrenTab;
