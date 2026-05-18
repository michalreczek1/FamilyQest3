import React, { useState } from 'react';
import { DAY_NAMES } from '../../constants.js';
import { normalizeTaskArchiveDays } from '../../lib/tasks.js';
import ModalOverlay from '../common/ModalOverlay.jsx';

const EditTaskModal = ({
  task,
  children,
  onSave,
  onClose
}) => {
  const [childId, setChildId] = useState(task?.childId || '');
  const [title, setTitle] = useState(task?.title || '');
  const [tier, setTier] = useState(task?.tier || 'MIN');
  const [points, setPoints] = useState(Number(task?.points || 0));
  const [description, setDescription] = useState(task?.description || '');
  const [daysOfWeek, setDaysOfWeek] = useState(normalizeTaskArchiveDays(task?.daysOfWeek).length > 0 ? normalizeTaskArchiveDays(task?.daysOfWeek) : [1, 2, 3, 4, 5, 6, 7]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const toggleDay = dayNum => {
    setDaysOfWeek(prev => prev.includes(dayNum) ? prev.filter(day => day !== dayNum) : [...prev, dayNum].sort((a, b) => a - b));
  };
  const handleSubmit = async e => {
    e.preventDefault();
    const cleanTitle = title.trim();
    if (!cleanTitle) {
      setError('Podaj nazwę zadania.');
      return;
    }
    if (!childId) {
      setError('Wybierz dziecko.');
      return;
    }
    if (daysOfWeek.length === 0) {
      setError('Wybierz przynajmniej jeden dzień tygodnia.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      await onSave({
        childId,
        title: cleanTitle,
        tier,
        points: Number(points || 0),
        description: description.trim(),
        daysOfWeek
      });
    } catch (saveError) {
      setError(saveError.message || 'Nie udało się zapisać zadania.');
      setSaving(false);
    }
  };
  return React.createElement(ModalOverlay, {
    className: "modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-label": "Edytuj zadanie"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, "Edytuj zadanie"), error && React.createElement("div", {
    className: "error"
  }, error), React.createElement("form", {
    onSubmit: handleSubmit
  }, React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dziecko"), React.createElement("select", {
    className: "select",
    value: childId,
    onChange: e => setChildId(e.target.value),
    required: true
  }, children.map(child => React.createElement("option", {
    key: child.id,
    value: child.id
  }, child.avatar, " ", child.name))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Nazwa zadania"), React.createElement("input", {
    type: "text",
    className: "input",
    value: title,
    onChange: e => setTitle(e.target.value),
    required: true,
    placeholder: "np. Pościel łóżko"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Typ zadania"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, ['MIN', 'PLUS', 'WEEKLY'].map(t => React.createElement("button", {
    key: t,
    type: "button",
    onClick: () => setTier(t),
    className: `badge badge-${t.toLowerCase()}`,
    style: {
      padding: '1rem 0.55rem',
      opacity: tier === t ? 1 : 0.55,
      border: tier === t ? '2px solid white' : '2px solid transparent',
      cursor: 'pointer',
      whiteSpace: 'normal',
      lineHeight: 1.15
    }
  }, t === 'MIN' ? '📋 Podstawowe' : t === 'PLUS' ? '⭐ Bonus' : '📅 Tygodniowe'))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Punkty"), React.createElement("input", {
    type: "number",
    className: "input",
    value: points,
    onChange: e => setPoints(parseInt(e.target.value || '0', 10) || 0),
    min: "0",
    max: "10000",
    placeholder: "0"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dni tygodnia"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(7, minmax(0, 1fr))',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, DAY_NAMES.map((day, index) => {
    const dayNum = index + 1;
    const active = daysOfWeek.includes(dayNum);
    return React.createElement("button", {
      key: dayNum,
      type: "button",
      onClick: () => toggleDay(dayNum),
      style: {
        padding: '0.75rem 0.45rem',
        background: active ? 'rgba(18, 183, 106, 0.3)' : 'rgba(255, 255, 255, 0.1)',
        border: active ? '2px solid #12B76A' : '2px solid rgba(255, 255, 255, 0.2)',
        borderRadius: '0.5rem',
        cursor: 'pointer',
        fontSize: '0.85rem',
        fontWeight: 600,
        color: 'white'
      }
    }, day);
  })), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Opis"), React.createElement("textarea", {
    className: "textarea",
    value: description,
    onChange: e => setDescription(e.target.value),
    placeholder: "np. Zaraz po wstaniu",
    rows: "3"
  }), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1rem'
    }
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onClose,
    disabled: saving,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    disabled: saving,
    style: {
      flex: 1
    }
  }, saving ? 'Zapisywanie...' : 'Zapisz zmiany')))));
};

export default EditTaskModal;
