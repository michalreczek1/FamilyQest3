import React from 'react';
import FamilyGoalWidget from '../leaderboard/FamilyGoalWidget.jsx';
import WeeklyLeaderboardPanel from '../leaderboard/WeeklyLeaderboardPanel.jsx';

const ChildSelectionView = ({
  children,
  streaks,
  points,
  leaderboardChildren = null,
  leaderboardStreaks = null,
  leaderboardPoints = null,
  familyGoal,
  evaluateDay,
  getDateString,
  onSelectChild,
  onParentMode,
  onLogout
}) => {
  return React.createElement("div", {
    className: "app-container"
  }, React.createElement("div", {
    className: "glass-card"
  }, React.createElement("div", {
    className: "header"
  }, React.createElement("button", {
    className: "btn btn-danger",
    onClick: onLogout
  }, "Wyloguj"), React.createElement("h1", null, "Wybierz profil"), React.createElement("button", {
    className: "btn btn-secondary",
    onClick: onParentMode
  }, "\uD83D\uDD10 Panel rodzica")), children.length === 0 ? React.createElement("div", {
    className: "empty-state"
  }, React.createElement("div", {
    style: {
      fontSize: '5rem'
    }
  }, "\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67\u200D\uD83D\uDC66"), React.createElement("p", null, "Brak dzieci. Przejd\u017A do panelu rodzica, aby doda\u0107 pierwsze dziecko.")) : React.createElement(React.Fragment, null, React.createElement("div", {
    className: "grid grid-3"
  }, children.map(child => React.createElement("div", {
    key: child.id,
    className: "glass-card child-card",
    onClick: () => onSelectChild(child)
  }, React.createElement("div", {
    className: "child-avatar"
  }, child.avatar), React.createElement("h2", {
    style: {
      textAlign: 'center'
    }
  }, child.name)))), React.createElement(WeeklyLeaderboardPanel, {
    children: leaderboardChildren || children,
    streaks: leaderboardStreaks || streaks,
    points: leaderboardPoints || points,
    title: "\uD83C\uDFC6 Ranking rodzinny"
  }), React.createElement("div", {
    style: {
      marginTop: '1.25rem'
    }
  }, React.createElement("h3", {
    style: {
      marginBottom: '1rem'
    }
  }, "\uD83C\uDFAF Cel rodzinny"), React.createElement(FamilyGoalWidget, {
    familyGoal: familyGoal,
    children: children,
    points: points,
    evaluateDay: evaluateDay,
    getDateString: getDateString
  })))));
};

export default ChildSelectionView;
