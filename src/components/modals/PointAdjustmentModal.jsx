import React, { useState } from 'react';
import ModalOverlay from '../common/ModalOverlay.jsx';

const PointAdjustmentModal = ({
  draft,
  onSave,
  onClose
}) => {
  const child = draft?.child;
  const type = draft?.type || 'BONUS';
  const isPenalty = type === 'PENALTY';
  const [pointsValue, setPointsValue] = useState('5');
  const [note, setNote] = useState(isPenalty ? 'Kara punktowa' : 'Premia punktowa');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  if (!child) return null;
  const submit = async event => {
    event.preventDefault();
    setError('');
    const points = Number.parseInt(pointsValue, 10);
    if (!Number.isFinite(points) || points <= 0) {
      setError('Podaj dodatnią liczbę punktów.');
      return;
    }
    setSaving(true);
    try {
      await onSave({
        child,
        type,
        points,
        note
      });
    } catch (e) {
      setError(e.message || 'Nie udało się zapisać zmiany punktów.');
    } finally {
      setSaving(false);
    }
  };
  return React.createElement(ModalOverlay, {
    className: "modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-labelledby": "point-adjustment-title"
  }, React.createElement("div", {
    className: "modal-content",
    style: {
      maxWidth: '520px'
    }
  }, React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      gap: '1rem',
      alignItems: 'center',
      marginBottom: '1rem'
    }
  }, React.createElement("h2", {
    id: "point-adjustment-title",
    style: {
      margin: 0
    }
  }, isPenalty ? "\u26A0\uFE0F Kara punktowa" : "\uD83C\uDF81 Premia punktowa"), React.createElement("button", {
    className: "btn btn-secondary",
    type: "button",
    onClick: onClose,
    title: "Zamknij"
  }, "\u2715")), React.createElement("div", {
    className: "task-item",
    style: {
      marginBottom: '1rem',
      cursor: 'default'
    }
  }, React.createElement("div", {
    style: {
      fontSize: '2.2rem'
    }
  }, child.avatar || "\uD83D\uDC64"), React.createElement("div", {
    style: {
      flex: 1
    }
  }, React.createElement("div", {
    style: {
      fontWeight: 800
    }
  }, child.name), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.75
    }
  }, isPenalty ? "Punkty zostan\u0105 odj\u0119te po zapisaniu." : "Punkty zostan\u0105 dodane po zapisaniu."))), React.createElement("form", {
    onSubmit: submit
  }, React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.4rem',
      fontWeight: 700
    }
  }, "Liczba punkt\xF3w"), React.createElement("input", {
    className: "input",
    type: "number",
    min: "1",
    max: "1000",
    value: pointsValue,
    onChange: e => setPointsValue(e.target.value),
    autoFocus: true
  }), React.createElement("label", {
    style: {
      display: 'block',
      margin: '1rem 0 0.4rem',
      fontWeight: 700
    }
  }, "Informacja dla dziecka"), React.createElement("textarea", {
    className: "input",
    rows: 3,
    maxLength: 180,
    value: note,
    onChange: e => setNote(e.target.value),
    placeholder: isPenalty ? "Za co odejmujemy punkty?" : "Za co przyznajemy premi\u0119?"
  }), error && React.createElement("div", {
    className: "badge",
    style: {
      marginTop: '0.75rem',
      background: 'rgba(249, 112, 102, 0.18)',
      color: '#FDA29B',
      border: '1px solid rgba(249, 112, 102, 0.45)'
    }
  }, error), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.75rem',
      marginTop: '1.25rem'
    }
  }, React.createElement("button", {
    className: "btn btn-secondary",
    type: "button",
    onClick: onClose,
    disabled: saving,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    className: isPenalty ? "btn btn-danger" : "btn btn-success",
    type: "submit",
    disabled: saving,
    style: {
      flex: 1
    }
  }, saving ? "Zapisywanie..." : isPenalty ? "Odejmij punkty" : "Dodaj premi\u0119")))));
};

export default PointAdjustmentModal;
