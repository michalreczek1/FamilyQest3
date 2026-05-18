import React, { useState } from 'react';
import { CHILD_AVATARS, DAY_NAMES } from '../../constants.js';
import { findAvailableChildAccessCode, isValidChildAccessCode } from '../../lib/tasks.js';
import ModalOverlay from '../common/ModalOverlay.jsx';

const EditChildModal = ({
  child,
  siblings,
  onSave,
  onClose
}) => {
  const [name, setName] = useState(child?.name || '');
  const [avatar, setAvatar] = useState(child?.avatar || '👧');
  const [customAvatar, setCustomAvatar] = useState('');
  const [activeDays, setActiveDays] = useState(Array.isArray(child?.activeDays) ? child.activeDays : [1, 2, 3, 4, 5]);
  const [accessCode, setAccessCode] = useState(child?.accessCode || '');
  const [error, setError] = useState('');
  const toggleDay = day => {
    if (activeDays.includes(day)) {
      setActiveDays(activeDays.filter(d => d !== day));
    } else {
      setActiveDays([...activeDays, day].sort((a, b) => a - b));
    }
  };
  const handleSubmit = e => {
    e.preventDefault();
    setError('');
    const normalizedName = name.trim();
    const normalizedAvatar = (customAvatar.trim() || avatar || '').trim();
    const normalizedCode = accessCode.replace(/\D/g, '').slice(0, 4);
    if (!normalizedName) {
      setError('Imię dziecka jest wymagane.');
      return;
    }
    if (!normalizedAvatar) {
      setError('Wybierz avatar dziecka.');
      return;
    }
    if (activeDays.length === 0) {
      setError('Wybierz co najmniej 1 dzień aktywny.');
      return;
    }
    if (!isValidChildAccessCode(normalizedCode)) {
      setError('Kod dziecka musi mieć dokładnie 4 cyfry.');
      return;
    }
    const uniqueCode = findAvailableChildAccessCode(siblings, normalizedCode, child.id);
    if (!uniqueCode) {
      setError('Nie udało się ustawić unikalnego kodu dziecka.');
      return;
    }
    onSave({
      name: normalizedName,
      avatar: normalizedAvatar,
      activeDays: [...new Set(activeDays)].sort((a, b) => a - b),
      accessCode: uniqueCode
    });
  };
  return React.createElement(ModalOverlay, {
    className: "modal"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, "Edytuj profil dziecka"), React.createElement("form", {
    onSubmit: handleSubmit
  }, error && React.createElement("div", {
    className: "error"
  }, error), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Imi\u0119"), React.createElement("input", {
    type: "text",
    className: "input",
    value: name,
    onChange: e => setName(e.target.value),
    required: true
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wybierz avatar"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(6, 1fr)',
      gap: '0.5rem',
      marginBottom: '1rem'
    }
  }, CHILD_AVATARS.map(av => React.createElement("button", {
    key: av,
    type: "button",
    onClick: () => {
      setAvatar(av);
      setCustomAvatar('');
    },
    style: {
      fontSize: '2rem',
      padding: '0.5rem',
      background: customAvatar ? 'rgba(255, 255, 255, 0.1)' : avatar === av ? 'rgba(254, 200, 75, 0.3)' : 'rgba(255, 255, 255, 0.1)',
      border: customAvatar ? '2px solid transparent' : avatar === av ? '2px solid #FEC84B' : '2px solid transparent',
      borderRadius: '1rem',
      cursor: 'pointer'
    }
  }, av))), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "W\u0142asny avatar (emoji)"), React.createElement("input", {
    type: "text",
    className: "input",
    value: customAvatar,
    onChange: e => setCustomAvatar(e.target.value),
    placeholder: "np. \uD83E\uDD16"
  }), React.createElement("div", {
    style: {
      fontSize: '0.9rem',
      opacity: 0.85,
      marginBottom: '1rem'
    }
  }, "Wybrany avatar: ", React.createElement("strong", null, customAvatar.trim() || avatar)), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Kod dziecka (4 cyfry)"), React.createElement("input", {
    type: "text",
    className: "input",
    value: accessCode,
    onChange: e => setAccessCode(e.target.value.replace(/\D/g, '').slice(0, 4)),
    inputMode: "numeric",
    maxLength: 4,
    required: true
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Dni aktywne"), React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(7, 1fr)',
      gap: '0.5rem',
      marginBottom: '1.5rem'
    }
  }, DAY_NAMES.map((day, index) => {
    const dayNum = index + 1;
    return React.createElement("button", {
      key: dayNum,
      type: "button",
      onClick: () => toggleDay(dayNum),
      style: {
        padding: '0.75rem 0.5rem',
        background: activeDays.includes(dayNum) ? 'rgba(18, 183, 106, 0.3)' : 'rgba(255, 255, 255, 0.1)',
        border: activeDays.includes(dayNum) ? '2px solid #12B76A' : '2px solid transparent',
        borderRadius: '0.5rem',
        cursor: 'pointer',
        fontSize: '0.85rem',
        fontWeight: 600,
        color: 'white'
      }
    }, day);
  })), React.createElement("div", {
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
  }, "Zapisz zmiany")))));
};

export default EditChildModal;
