import React from 'react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, info) {
    console.error('Panel render error:', error, info);
  }

  handleReset = () => {
    this.setState({ hasError: false });
    this.props.onReset?.();
  };

  handleLogout = () => {
    this.setState({ hasError: false });
    this.props.onLogout?.();
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return React.createElement("div", {
      className: "app-container"
    }, React.createElement("div", {
      className: "glass-card error-boundary-card"
    }, React.createElement("h1", null, this.props.title || "Panel wymaga odświeżenia"), React.createElement("p", null, this.props.message || "Wystąpił błąd widoku. Dane są bezpieczne, spróbuj odświeżyć panel."), React.createElement("div", {
      className: "error-boundary-actions"
    }, React.createElement("button", {
      type: "button",
      className: "btn btn-primary",
      onClick: this.handleReset
    }, "Odśwież panel"), React.createElement("button", {
      type: "button",
      className: "btn btn-secondary",
      onClick: this.handleLogout
    }, "Wróć do logowania"))));
  }
}

export default ErrorBoundary;
