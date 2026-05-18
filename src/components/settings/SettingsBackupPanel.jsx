import React, { useState } from 'react';

const SettingsBackupPanel = ({
  familyGoal,
  onFamilyGoalChange,
  onExport,
  onImport
}) => {
  const [title, setTitle] = useState(familyGoal?.title || 'Cel rodzinny');
  const [target, setTarget] = useState(String(familyGoal?.target || 500));
  const [mode, setMode] = useState(familyGoal?.mode || 'points');
  const [message, setMessage] = useState('');
  return React.createElement("div", {
    className: "glass-card"
  }, React.createElement("h3", {
    style: {
      marginBottom: '0.75rem'
    }
  }, "\uD83E\uDDF0 Backup i cel rodzinny"), message && React.createElement("div", {
    className: "success"
  }, message), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Cel rodzinny"), React.createElement("input", {
    className: "input",
    placeholder: "Nazwa celu",
    value: title,
    onChange: e => setTitle(e.target.value)
  }), React.createElement("input", {
    className: "input",
    type: "number",
    min: "1",
    placeholder: "Pr\xF3g",
    value: target,
    onChange: e => setTarget(e.target.value)
  }), React.createElement("select", {
    className: "select",
    value: mode,
    onChange: e => setMode(e.target.value)
  }, React.createElement("option", {
    value: "points"
  }, "Suma punkt\xF3w rodziny"), React.createElement("option", {
    value: "passedDays"
  }, "Liczba zaliczonych dni rodziny")), React.createElement("button", {
    className: "btn btn-primary",
    style: {
      width: '100%',
      marginBottom: '1rem'
    },
    onClick: () => {
      onFamilyGoalChange({
        title: title.trim() || 'Cel rodzinny',
        target: Math.max(1, parseInt(target || '1', 10)),
        mode
      });
      setMessage('Cel rodzinny został zapisany.');
    }
  }, "Zapisz cel"), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Backup"), React.createElement("div", {
    style: {
      display: 'flex',
      gap: '0.5rem'
    }
  }, React.createElement("button", {
    className: "btn btn-secondary",
    style: {
      flex: 1
    },
    onClick: onExport
  }, "Eksport JSON"), React.createElement("label", {
    className: "btn btn-secondary",
    style: {
      flex: 1,
      textAlign: 'center'
    }
  }, "Import JSON", React.createElement("input", {
    type: "file",
    accept: "application/json",
    style: {
      display: 'none'
    },
    onChange: async e => {
      const file = e.target.files?.[0];
      if (!file) return;
      const text = await file.text();
      try {
        const result = await onImport(text);
        const restored = result?.restored || {};
        setMessage(`Backup został odtworzony. Dzieci: ${restored.children ?? '?'}, zadania: ${restored.tasks ?? '?'}.`);
      } catch (err) {
        setMessage('Import nieudany: ' + err.message);
      }
      e.target.value = '';
    }
  }))));
};

export default SettingsBackupPanel;
