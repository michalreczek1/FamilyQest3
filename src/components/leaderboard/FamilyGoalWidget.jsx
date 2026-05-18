import React from 'react';
import { HISTORY_DAYS } from '../../constants.js';

const FamilyGoalWidget = ({
  familyGoal,
  children,
  points,
  evaluateDay,
  getDateString
}) => {
  const today = getDateString();
  const totalPoints = children.reduce((sum, child) => sum + (points[child.id] || 0), 0);
  const totalPassedDays = children.reduce((sum, child) => {
    let passed = 0;
    for (let i = 0; i < HISTORY_DAYS; i++) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      const status = evaluateDay(child.id, getDateString(date));
      if (status === 'PASSED') passed += 1;
    }
    return sum + passed;
  }, 0);
  const mode = familyGoal?.mode || 'points';
  const currentValue = mode === 'passedDays' ? totalPassedDays : totalPoints;
  const target = Number(familyGoal?.target || 1);
  const progress = Math.max(0, Math.min(100, Math.round(currentValue / Math.max(target, 1) * 100)));
  return React.createElement("div", {
    className: "glass-card"
  }, React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: '0.5rem',
      marginBottom: '0.45rem'
    }
  }, React.createElement("span", {
    className: "goal-icon",
    style: {
      fontSize: '1.2rem'
    },
    "aria-hidden": "true"
  }, "\uD83C\uDFC6"), React.createElement("div", {
    style: {
      fontWeight: 700
    }
  }, familyGoal?.title || 'Cel rodzinny')), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.8
    }
  }, mode === 'passedDays' ? 'Tryb: liczba zaliczonych dni' : 'Tryb: suma punktów rodziny'), React.createElement("div", {
    style: {
      marginTop: '0.5rem',
      fontWeight: 600
    }
  }, currentValue, " / ", target), React.createElement("div", {
    className: "progress-bar"
  }, React.createElement("div", {
    className: "progress-fill",
    style: {
      width: `${progress}%`
    }
  })));
};

export default FamilyGoalWidget;
