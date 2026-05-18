import React from 'react';
import WeeklyLeaderboardPanel from '../../leaderboard/WeeklyLeaderboardPanel.jsx';

const StatsTab = ({
  activeChildren,
  streaks,
  points,
  getDateString,
  evaluateDay,
}) => {
  return React.createElement(React.Fragment, null, React.createElement("h2", {
      style: {
        marginBottom: '1rem'
      }
    }, "Statystyki rodziny"), React.createElement("div", {
      className: "grid grid-3"
    }, activeChildren.map(child => {
      const childStreak = streaks[child.id] || {
        current: 0,
        best: 0,
        idealWeeksCount: 0,
        idealWeeksInRow: 0
      };
      const childPoints = points[child.id] || 0;
      const today = getDateString();
      const status = evaluateDay(child.id, today);
      return React.createElement("div", {
        key: child.id,
        className: "glass-card"
      }, React.createElement("div", {
        className: "child-avatar",
        style: {
          fontSize: '3rem'
        }
      }, child.avatar), React.createElement("h3", {
        style: {
          textAlign: 'center',
          marginBottom: '1rem'
        }
      }, child.name), React.createElement("div", {
        style: {
          marginBottom: '0.5rem'
        }
      }, React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Status dzisiaj"), React.createElement("div", {
        style: {
          fontSize: '1.2rem',
          fontWeight: 600
        }
      }, status === 'PASSED' ? '✅ Zaliczony' : status === 'FAILED' ? '❌ Niezaliczony' : '⊘ Nieaktywny')), React.createElement("div", {
        style: {
          marginBottom: '0.5rem'
        }
      }, React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Punkty"), React.createElement("div", {
        style: {
          fontSize: '2rem',
          fontWeight: 700
        }
      }, childPoints)), React.createElement("div", null, React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Passa"), React.createElement("div", {
        style: {
          fontSize: '2rem',
          fontWeight: 700
        }
      }, childStreak.current, " dni"), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Rekord: ", childStreak.best), React.createElement("div", {
        style: {
          fontSize: '0.9rem',
          opacity: 0.7
        }
      }, "Idealne tygodnie: ", childStreak.idealWeeksCount || 0)));
    })), React.createElement(WeeklyLeaderboardPanel, {
      children: activeChildren,
      streaks: streaks,
      points: points
    }));
};

export default StatsTab;
