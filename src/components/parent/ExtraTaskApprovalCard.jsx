import React, { useState } from 'react';

const ExtraTaskApprovalCard = ({
  extraTask,
  child,
  onApprove,
  onReject
}) => {
  const [pointsValue, setPointsValue] = useState(String(Number.isFinite(Number(extraTask?.points)) ? extraTask.points : 1));
  if (!extraTask || !child) return null;
  return React.createElement("div", {
    className: "task-item"
  }, React.createElement("div", {
    style: {
      fontSize: '2rem'
    }
  }, child.avatar), React.createElement("div", {
    style: {
      flex: 1
    }
  }, React.createElement("div", {
    style: {
      fontWeight: 700
    }
  }, extraTask.title), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.7
    }
  }, child.name, " \u2022 ", extraTask.date, " \u2022 zadanie dodatkowe")), React.createElement("input", {
    className: "input",
    type: "number",
    min: "0",
    max: "1000",
    value: pointsValue,
    onChange: e => setPointsValue(e.target.value),
    style: {
      width: '92px'
    },
    "aria-label": "Punkty za zadanie dodatkowe"
  }), React.createElement("button", {
    className: "btn btn-success",
    onClick: () => onApprove(extraTask, pointsValue),
    title: "Zatwierd\u017A zadanie dodatkowe"
  }, "\u2705 Zatwierd\u017A"), React.createElement("button", {
    className: "btn btn-danger",
    onClick: () => onReject(extraTask),
    title: "Odrzu\u0107 zadanie dodatkowe"
  }, "\u274C Odrzu\u0107"));
};

export default ExtraTaskApprovalCard;
