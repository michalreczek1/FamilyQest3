import React, { useEffect, useState } from 'react';

const SettingsSecurityPanel = ({
  user,
  parentUsers,
  onRefreshParents,
  onAddParent,
  onToggleParent,
  onChangePassword,
  onResetPassword,
  onChangePin
}) => {
  const [newParentEmail, setNewParentEmail] = useState('');
  const [newParentPassword, setNewParentPassword] = useState('');
  const [newParentPin, setNewParentPin] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [pinPassword, setPinPassword] = useState('');
  const [newPin, setNewPin] = useState('');
  const [repeatPin, setRepeatPin] = useState('');
  const [resetPasswordValue, setResetPasswordValue] = useState('');
  const [resetTarget, setResetTarget] = useState('');
  const [message, setMessage] = useState('');
  useEffect(() => {
    onRefreshParents();
  }, []);
  return React.createElement("div", {
    className: "glass-card"
  }, React.createElement("h3", {
    style: {
      marginBottom: '0.75rem'
    }
  }, "\uD83D\uDD10 Konta i bezpiecze\u0144stwo"), message && React.createElement("div", {
    className: "success"
  }, message), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Dodaj konto rodzica (nieaktywne)"), React.createElement("input", {
    className: "input",
    placeholder: "Email",
    value: newParentEmail,
    onChange: e => setNewParentEmail(e.target.value)
  }), React.createElement("input", {
    className: "input",
    placeholder: "Has\u0142o tymczasowe",
    type: "password",
    value: newParentPassword,
    onChange: e => setNewParentPassword(e.target.value)
  }), React.createElement("input", {
    className: "input",
    placeholder: "PIN rodzica (6 cyfr, opcjonalnie)",
    type: "password",
    value: newParentPin,
    onChange: e => setNewParentPin(e.target.value.replace(/\D/g, '').slice(0, 6)),
    inputMode: "numeric",
    maxLength: 6
  }), React.createElement("button", {
    className: "btn btn-primary",
    style: {
      width: '100%',
      marginBottom: '1rem'
    },
    onClick: async () => {
      try {
        await onAddParent({
          email: newParentEmail,
          password: newParentPassword,
          pinCode: newParentPin || undefined
        });
        setMessage('Dodano konto rodzica. Czeka na aktywację.');
        setNewParentEmail('');
        setNewParentPassword('');
        setNewParentPin('');
      } catch (e) {
        setMessage(e.message);
      }
    }
  }, "+ Dodaj rodzica"), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "U\u017Cytkownicy rodzice"), parentUsers.map(parent => React.createElement("div", {
    key: parent.id,
    className: "history-day"
  }, React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      gap: '1rem',
      alignItems: 'center'
    }
  }, React.createElement("div", null, React.createElement("div", {
    style: {
      fontWeight: 600
    }
  }, parent.email), React.createElement("div", {
    style: {
      fontSize: '0.8rem',
      opacity: 0.8
    }
  }, parent.active ? 'Aktywne' : 'Nieaktywne', " \u2022 ", parent.hasPinCode ? 'PIN ustawiony' : 'Brak PIN-u', " \u2022 ", (parent.createdAt || '').slice(0, 10), parent.id === user?.id ? ' • Twoje konto' : '')), React.createElement("button", {
    className: parent.active ? 'btn btn-danger' : 'btn btn-success',
    onClick: () => onToggleParent(parent.id, !parent.active)
  }, parent.active ? 'Dezaktywuj' : 'Aktywuj')))), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Zmie\u0144 PIN rodzica"), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Aktualne has\u0142o",
    value: pinPassword,
    onChange: e => setPinPassword(e.target.value)
  }), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Nowy PIN (6 cyfr)",
    value: newPin,
    onChange: e => setNewPin(e.target.value.replace(/\D/g, '').slice(0, 6)),
    inputMode: "numeric",
    maxLength: 6
  }), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Powt\u00F3rz PIN",
    value: repeatPin,
    onChange: e => setRepeatPin(e.target.value.replace(/\D/g, '').slice(0, 6)),
    inputMode: "numeric",
    maxLength: 6
  }), React.createElement("button", {
    className: "btn btn-secondary",
    style: {
      width: '100%',
      marginBottom: '1rem'
    },
    onClick: async () => {
      try {
        if (newPin.length !== 6) throw new Error('PIN musi mieć dokładnie 6 cyfr');
        if (newPin !== repeatPin) throw new Error('Powtórzony PIN jest inny');
        await onChangePin(pinPassword, newPin);
        setPinPassword('');
        setNewPin('');
        setRepeatPin('');
        setMessage('PIN rodzica został zmieniony.');
      } catch (e) {
        setMessage(e.message);
      }
    }
  }, "Zmie\u0144 PIN"), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Zmie\u0144 has\u0142o"), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Aktualne has\u0142o",
    value: currentPassword,
    onChange: e => setCurrentPassword(e.target.value)
  }), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Nowe has\u0142o",
    value: newPassword,
    onChange: e => setNewPassword(e.target.value)
  }), React.createElement("button", {
    className: "btn btn-secondary",
    style: {
      width: '100%',
      marginBottom: '1rem'
    },
    onClick: async () => {
      try {
        await onChangePassword(currentPassword, newPassword);
        setCurrentPassword('');
        setNewPassword('');
        setMessage('Hasło zostało zmienione.');
      } catch (e) {
        setMessage(e.message);
      }
    }
  }, "Zmie\u0144 has\u0142o"), React.createElement("h4", {
    style: {
      marginBottom: '0.5rem'
    }
  }, "Reset has\u0142a u\u017Cytkownika"), React.createElement("select", {
    className: "select",
    value: resetTarget,
    onChange: e => setResetTarget(e.target.value)
  }, React.createElement("option", {
    value: ""
  }, "Wybierz konto"), parentUsers.map(parent => React.createElement("option", {
    key: parent.id,
    value: parent.id
  }, parent.email))), React.createElement("input", {
    className: "input",
    type: "password",
    placeholder: "Nowe has\u0142o dla wybranego konta",
    value: resetPasswordValue,
    onChange: e => setResetPasswordValue(e.target.value)
  }), React.createElement("button", {
    className: "btn btn-secondary",
    style: {
      width: '100%'
    },
    onClick: async () => {
      try {
        if (!resetTarget) throw new Error('Wybierz konto do resetu');
        await onResetPassword(resetTarget, resetPasswordValue);
        setResetPasswordValue('');
        setMessage('Hasło użytkownika zostało zresetowane.');
      } catch (e) {
        setMessage(e.message);
      }
    }
  }, "Resetuj has\u0142o"));
};

export default SettingsSecurityPanel;
