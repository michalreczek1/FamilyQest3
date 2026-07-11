import React, { useState } from 'react';
import ModalOverlay from '../common/ModalOverlay.jsx';

const AddRewardModal = ({
  onAdd,
  onSave,
  reward = null,
  onClose
}) => {
  const isEditing = Boolean(reward);
  const [title, setTitle] = useState(reward?.title || '');
  const [description, setDescription] = useState(reward?.description || '');
  const [requiredPoints, setRequiredPoints] = useState(reward?.requiredPoints ? String(reward.requiredPoints) : '');
  const [requiredStreak, setRequiredStreak] = useState(reward?.requiredStreak ? String(reward.requiredStreak) : '');
  const [requiredIdealWeeks, setRequiredIdealWeeks] = useState(reward?.requiredIdealWeeks ? String(reward.requiredIdealWeeks) : '');
  const handleSubmit = e => {
    e.preventDefault();
    const payload = {
      title: title.trim(),
      description: description.trim(),
      requiredPoints: requiredPoints ? parseInt(requiredPoints, 10) : null,
      requiredStreak: requiredStreak ? parseInt(requiredStreak, 10) : null,
      requiredIdealWeeks: requiredIdealWeeks ? parseInt(requiredIdealWeeks, 10) : null
    };
    if (isEditing) {
      onSave(payload);
    } else {
      onAdd(payload.title, payload.description, payload.requiredPoints, payload.requiredStreak, payload.requiredIdealWeeks);
    }
  };
  return React.createElement(ModalOverlay, {
    className: "modal"
  }, React.createElement("div", {
    className: "modal-content"
  }, React.createElement("h2", {
    style: {
      marginBottom: '1.5rem'
    }
  }, isEditing ? "Edytuj nagrod\u0119" : "Dodaj nagrod\u0119"), React.createElement("form", {
    onSubmit: handleSubmit
  }, React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Nazwa nagrody"), React.createElement("input", {
    type: "text",
    className: "input",
    value: title,
    onChange: e => setTitle(e.target.value),
    required: true,
    placeholder: "np. 30 minut gier"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Opis"), React.createElement("textarea", {
    className: "textarea",
    value: description,
    onChange: e => setDescription(e.target.value),
    placeholder: "np. Dodatkowy czas na granie",
    rows: "2"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wymagane punkty (opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: requiredPoints,
    onChange: e => setRequiredPoints(e.target.value),
    min: "0",
    placeholder: "np. 50"
  }), React.createElement("div", {
    style: {
      fontSize: '0.82rem',
      opacity: 0.7,
      marginTop: '-0.2rem',
      marginBottom: '0.9rem'
    }
  }, "Nagroda punktowa odblokowuje się przy każdym kolejnym pełnym progu, np. 50, 100, 150 pkt."), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wymagana passa (dni z rz\u0119du, opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: requiredStreak,
    onChange: e => setRequiredStreak(e.target.value),
    min: "0",
    placeholder: "np. 7"
  }), React.createElement("label", {
    style: {
      display: 'block',
      marginBottom: '0.5rem',
      opacity: 0.8
    }
  }, "Wymagane idealne tygodnie z rz\u0119du (opcjonalne)"), React.createElement("input", {
    type: "number",
    className: "input",
    value: requiredIdealWeeks,
    onChange: e => setRequiredIdealWeeks(e.target.value),
    min: "0",
    placeholder: "np. 2"
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
  }, isEditing ? "Zapisz" : "Dodaj nagrod\u0119")))));
};


export default AddRewardModal;
