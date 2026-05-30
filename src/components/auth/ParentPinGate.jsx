import React, { useEffect, useRef, useState } from 'react';

const normalizePin = value => String(value || '').replace(/\D/g, '').slice(0, 6);

const ParentPinGate = ({
  hasPinCode,
  onVerify,
  onSetup,
  onCancel,
}) => {
  const [pinCode, setPinCode] = useState('');
  const [repeatPinCode, setRepeatPinCode] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [lockedUntil, setLockedUntil] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const pinInputRef = useRef(null);
  const isSetupMode = !hasPinCode;
  const lockSecondsLeft = lockedUntil > now ? Math.max(1, Math.ceil((lockedUntil - now) / 1000)) : 0;
  const isLocked = lockSecondsLeft > 0;

  useEffect(() => {
    pinInputRef.current?.focus();
  }, []);

  useEffect(() => {
    if (!lockedUntil) return undefined;
    const updateLock = () => {
      const nextNow = Date.now();
      setNow(nextNow);
      if (nextNow >= lockedUntil) {
        setLockedUntil(0);
        setError(current => current.includes('Za dużo błędnych PIN-ów') || current.includes('Panel rodzica jest chwilowo') ? '' : current);
      }
    };
    const interval = window.setInterval(updateLock, 250);
    updateLock();
    return () => window.clearInterval(interval);
  }, [lockedUntil]);

  const submit = async event => {
    event.preventDefault();
    setError('');
    if (isLocked) {
      setError(`Panel rodzica jest chwilowo zablokowany. Spróbuj za ${lockSecondsLeft} s.`);
      return;
    }
    if (pinCode.length !== 6) {
      setError('PIN musi mieć dokładnie 6 cyfr.');
      return;
    }
    if (isSetupMode && pinCode !== repeatPinCode) {
      setError('Powtórzony PIN jest inny.');
      return;
    }
    if (isSetupMode && !currentPassword) {
      setError('Podaj aktualne hasło rodzica.');
      return;
    }

    setSubmitting(true);
    const result = isSetupMode
      ? await onSetup({ pinCode, currentPassword })
      : await onVerify(pinCode);
    if (!result?.success) {
      setError(result?.error || 'Nie udało się otworzyć panelu rodzica.');
      if (result?.retryAfterSeconds) {
        setLockedUntil(Date.now() + Number(result.retryAfterSeconds) * 1000);
      }
      setPinCode('');
      setRepeatPinCode('');
      setSubmitting(false);
      requestAnimationFrame(() => pinInputRef.current?.focus());
      return;
    }
    setSubmitting(false);
  };

  return React.createElement("div", {
    className: "modal parent-pin-modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-labelledby": "parent-pin-title"
  }, React.createElement("div", {
    className: "modal-content parent-pin-card"
  }, React.createElement("div", {
    className: "parent-pin-header"
  }, React.createElement("div", {
    className: "parent-pin-icon",
    "aria-hidden": "true"
  }, "🔐"), React.createElement("div", null, React.createElement("h2", {
    id: "parent-pin-title"
  }, isSetupMode ? 'Ustaw PIN rodzica' : 'PIN rodzica'), React.createElement("p", null, isSetupMode ? 'Utwórz 6-cyfrowy PIN wymagany przy każdym wejściu do panelu.' : 'Wpisz 6-cyfrowy PIN, aby wejść do panelu.'))), React.createElement("form", {
    onSubmit: submit
  }, error && React.createElement("div", {
    className: "error",
    role: "alert"
  }, error), React.createElement("input", {
    ref: pinInputRef,
    type: "password",
    className: "input parent-pin-input",
    placeholder: "6-cyfrowy PIN",
    value: pinCode,
    onChange: event => setPinCode(normalizePin(event.target.value)),
    inputMode: "numeric",
    autoComplete: "one-time-code",
    pattern: "\\d{6}",
    maxLength: 6,
    required: true,
    disabled: submitting || isLocked
  }), isSetupMode && React.createElement(React.Fragment, null, React.createElement("input", {
    type: "password",
    className: "input parent-pin-input",
    placeholder: "Powtórz PIN",
    value: repeatPinCode,
    onChange: event => setRepeatPinCode(normalizePin(event.target.value)),
    inputMode: "numeric",
    autoComplete: "one-time-code",
    pattern: "\\d{6}",
    maxLength: 6,
    required: true,
    disabled: submitting || isLocked
  }), React.createElement("input", {
    type: "password",
    className: "input",
    placeholder: "Aktualne hasło rodzica",
    value: currentPassword,
    onChange: event => setCurrentPassword(event.target.value),
    autoComplete: "current-password",
    required: true,
    disabled: submitting || isLocked
  })), isLocked && React.createElement("div", {
    className: "parent-pin-lockout",
    role: "status"
  }, "Blokada po 3 błędnych PIN-ach. Spróbuj za ", lockSecondsLeft, " s."), React.createElement("div", {
    className: "parent-pin-actions"
  }, React.createElement("button", {
    type: "button",
    className: "btn btn-secondary",
    onClick: onCancel,
    disabled: submitting
  }, "Anuluj"), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    disabled: submitting || isLocked || pinCode.length !== 6 || (isSetupMode && (repeatPinCode.length !== 6 || !currentPassword))
  }, isLocked ? `${lockSecondsLeft} s` : submitting ? 'Sprawdzanie...' : isSetupMode ? 'Ustaw i wejdź' : 'Wejdź')))));
};

export default ParentPinGate;
