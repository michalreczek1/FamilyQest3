import React, { useState } from 'react';
import { DAY_NAMES } from '../../constants.js';
import { TASK_TEMPLATES } from '../../lib/tasks.js';
import ModalOverlay from '../common/ModalOverlay.jsx';

const AddTaskModal = ({
  children,
  onAdd,
  onClose
}) => {
  const [childId, setChildId] = useState(children.length > 1 ? 'ALL' : children[0]?.id || '');
  const [title, setTitle] = useState('');
  const [tier, setTier] = useState('MIN');
  const [points, setPoints] = useState(0);
  const [description, setDescription] = useState('');
  const [daysOfWeek, setDaysOfWeek] = useState([1, 2, 3, 4, 5, 6, 7]);
  const [templateId, setTemplateId] = useState('');
  const templatesForTier = TASK_TEMPLATES.filter(t => t.tier === tier);
  const applyTemplate = id => {
    const template = TASK_TEMPLATES.find(t => t.id === id);
    if (!template) return;
    setTemplateId(template.id);
    setTier(template.tier);
    setTitle(template.title);
    setPoints(template.points);
    setDescription(template.description || '');
  };
  const toggleDay = dayNum => {
    setDaysOfWeek(prev => prev.includes(dayNum) ? prev.filter(day => day !== dayNum) : [...prev, dayNum].sort((a, b) => a - b));
  };
  const handleSubmit = e => {
    e.preventDefault();
    if (!childId) return;
    onAdd(childId, title, tier, points, description, daysOfWeek);
  };
  return React.createElement(ModalOverlay, {
    className: "modal"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, "Dodaj zadanie"), React.createElement("form", {
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
  }, children.length > 1 && React.createElement("option", {
    value: "ALL"
  }, "Wszystkie dzieci"), children.map(child => React.createElement("option", {
    key: child.id,
    value: child.id
  }, child.avatar, " ", child.name))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Tytu\u0142 zadania"), React.createElement("input", {
    type: "text",
    className: "input",
    value: title,
    onChange: e => setTitle(e.target.value),
    required: true,
    placeholder: "np. Po\u015Bciel \u0142\xF3\u017Cko"
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
  }, "Typ zadania"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(3, 1fr)',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, ['MIN', 'PLUS', 'WEEKLY'].map(t => React.createElement("button", {
    key: t,
    type: "button",
    onClick: () => {
      setTier(t);
      setTemplateId('');
    },
    className: `badge badge-${t.toLowerCase()}`,
    style: {
      padding: '1rem',
      opacity: tier === t ? 1 : 0.5,
      border: tier === t ? '2px solid white' : '2px solid transparent',
      cursor: 'pointer'
    }
  }, t === 'MIN' ? '📋 MINIMUM' : t === 'PLUS' ? '⭐ BONUS' : '📅 TYGODNIOWE'))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Szablon (opcjonalnie)"), React.createElement("select", {
    className: "select",
    value: templateId,
    onChange: e => applyTemplate(e.target.value)
  }, React.createElement("option", {
    value: ""
  }, "W\u0142asne zadanie"), templatesForTier.map(template => React.createElement("option", {
    key: template.id,
    value: template.id
  }, template.title, " (+", template.points, " pkt)"))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Punkty (opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: points,
    onChange: e => setPoints(parseInt(e.target.value) || 0),
    min: "0",
    placeholder: "0"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Opis (opcjonalny)"), React.createElement("textarea", {
    className: "textarea",
    value: description,
    onChange: e => setDescription(e.target.value),
    placeholder: "np. Zaraz po wstaniu",
    rows: "2"
  }), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '1rem'
    }
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onClose,
    style: {
      flex: 1
    }
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    style: {
      flex: 1
    }
  }, "Dodaj zadanie")))));
};

export default AddTaskModal;
