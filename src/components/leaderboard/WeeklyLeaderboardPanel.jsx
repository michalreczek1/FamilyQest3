import React from 'react';
import { getLeaderboardPoints, rankIcon, sortChildrenForLeaderboard } from '../../lib/leaderboard.js';

const WeeklyLeaderboardPanel = ({
  children,
  streaks,
  points,
  title = '📊 Ranking tygodniowy'
}) => {
  const rankedChildren = sortChildrenForLeaderboard(children, streaks, points);
  return React.createElement("div", {
    className: "glass-card",
    style: {
      marginTop: '1.25rem'
    }
  }, React.createElement("h3", {
    style: {
      marginBottom: '1rem'
    }
  }, title), rankedChildren.length === 0 ? React.createElement("div", {
    className: "empty-state"
  }, "Brak dzieci") : rankedChildren.map((child, index) => {
    const childStreak = streaks[child.id] || {
      current: 0,
      idealWeeksInRow: 0
    };
    const childPoints = getLeaderboardPoints(points[child.id]);
    return React.createElement("div", {
      key: child.id,
      className: "task-item"
    }, React.createElement("div", {
      style: {
        fontSize: '2rem',
        fontWeight: 700,
        width: '50px',
        textAlign: 'center'
      }
    }, rankIcon(index)), React.createElement("div", {
      style: {
        fontSize: '2rem'
      }
    }, child.avatar), React.createElement("div", {
      style: {
        flex: 1
      }
    }, React.createElement("div", {
      style: {
        fontWeight: 600
      }
    }, child.name), React.createElement("div", {
      style: {
        fontSize: '0.9rem',
        opacity: 0.78
      }
    }, "Idealne tyg.: ", childStreak.idealWeeksInRow || 0, " \u2022 Passa: ", childStreak.current || 0, " \u2022 ", childPoints, " pkt")));
  }));
};

export default WeeklyLeaderboardPanel;
