import React, { useState } from 'react';

const LoginView = ({
  onLogin,
  onRegister,
  onChildLogin,
  onForgotPassword,
  onResetPassword
}) => {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [familyName, setFamilyName] = useState('');
  const [childCode, setChildCode] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const switchMode = nextMode => {
    setMode(nextMode);
    setError('');
    setSuccess('');
  };
  const getSubtitle = () => {
    if (mode === 'register') return 'Załóż konto rodzica';
    if (mode === 'child') return 'Zaloguj dziecko kodem dostępu';
    if (mode === 'forgot') return 'Reset hasła rodzica';
    if (mode === 'reset') return 'Ustaw nowe hasło';
    return 'Zaloguj się do konta rodzica';
  };
  const getSubmitLabel = () => {
    if (mode === 'register') return 'Utwórz konto';
    if (mode === 'child') return 'Zaloguj dziecko';
    if (mode === 'forgot') return 'Wyślij reset';
    if (mode === 'reset') return 'Zmień hasło';
    return 'Zaloguj się';
  };
  const handleSubmit = async e => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSubmitting(true);
    let result = null;
    if (mode === 'login') {
      result = await onLogin(email, password);
    } else if (mode === 'register') {
      result = await onRegister({
        email,
        password,
        familyName
      });
    } else if (mode === 'child') {
      result = await onChildLogin(childCode);
    } else if (mode === 'forgot') {
      result = await onForgotPassword(email);
    } else {
      result = await onResetPassword(resetToken, password);
    }
    if (!result?.success) {
      setError(result?.error || 'Operacja nie powiodła się');
      setSubmitting(false);
      return;
    }
    if (mode === 'forgot') {
      const debugTokenText = result.debugResetToken ? ` Token testowy: ${result.debugResetToken}` : '';
      setSuccess((result.message || 'Wysłano instrukcję resetu.') + debugTokenText);
      if (result.debugResetToken) setResetToken(result.debugResetToken);
      setMode('reset');
    } else if (mode === 'reset') {
      setSuccess(result.message || 'Hasło zostało zmienione.');
      setPassword('');
      setResetToken('');
      setMode('login');
    }
    setSubmitting(false);
  };
  return React.createElement("div", {
    className: "app-container"
  }, React.createElement("div", {
    className: "glass-card",
    style: {
      maxWidth: '560px',
      margin: '5rem auto'
    }
  }, React.createElement("div", {
    style: {
      textAlign: 'center',
      marginBottom: '1.2rem'
    }
  }, React.createElement("div", {
    style: {
      fontSize: '5rem'
    }
  }, "\uD83C\uDFC6"), React.createElement("h1", null, "FamilyQuest"), React.createElement("p", {
    style: {
      opacity: 0.8
    }
  }, getSubtitle())), React.createElement("div", {
    className: "tabs",
    style: {
      justifyContent: 'center',
      marginBottom: '1rem'
    }
  }, React.createElement("button", {
    className: `tab ${mode === 'login' ? 'active' : ''}`,
    onClick: () => switchMode('login')
  }, "Rodzic"), React.createElement("button", {
    className: `tab ${mode === 'register' ? 'active' : ''}`,
    onClick: () => switchMode('register')
  }, "Rejestracja"), React.createElement("button", {
    className: `tab ${mode === 'child' ? 'active' : ''}`,
    onClick: () => switchMode('child')
  }, "Dziecko"), React.createElement("button", {
    className: `tab ${mode === 'forgot' ? 'active' : ''}`,
    onClick: () => switchMode('forgot')
  }, "Reset")), React.createElement("form", {
    onSubmit: handleSubmit
  }, error && React.createElement("div", {
    className: "error"
  }, error), success && React.createElement("div", {
    className: "success"
  }, success), (mode === 'login' || mode === 'register' || mode === 'forgot') && React.createElement("input", {
    type: "email",
    className: "input",
    placeholder: "Email rodzica",
    value: email,
    onChange: e => setEmail(e.target.value),
    required: true
  }), (mode === 'login' || mode === 'register' || mode === 'reset') && React.createElement("input", {
    type: "password",
    className: "input",
    placeholder: mode === 'reset' ? 'Nowe hasło' : 'Hasło',
    value: password,
    onChange: e => setPassword(e.target.value),
    required: true
  }), mode === 'register' && React.createElement(React.Fragment, null, React.createElement("input", {
    type: "text",
    className: "input",
    placeholder: "Nazwa rodziny (np. Rodzina Kowalskich)",
    value: familyName,
    onChange: e => setFamilyName(e.target.value)
  })), mode === 'child' && React.createElement("input", {
    type: "password",
    className: "input",
    placeholder: "Kod dziecka (4 cyfry)",
    value: childCode,
    onChange: e => setChildCode(e.target.value.replace(/\D/g, '').slice(0, 4)),
    inputMode: "numeric",
    autoComplete: "one-time-code",
    maxLength: 4,
    required: true
  }), mode === 'reset' && React.createElement("input", {
    type: "text",
    className: "input",
    placeholder: "Token resetu",
    value: resetToken,
    onChange: e => setResetToken(e.target.value),
    required: true
  }), React.createElement("button", {
    type: "submit",
    className: "btn btn-primary",
    style: {
      width: '100%'
    },
    disabled: submitting
  }, submitting ? 'Przetwarzanie...' : getSubmitLabel()))));
};

export default LoginView;
