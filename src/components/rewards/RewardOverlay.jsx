import React, { useEffect } from 'react';
import ModalOverlay from '../common/ModalOverlay.jsx';

const RewardOverlay = ({
  reward,
  onClose
}) => {
  useEffect(() => {
    if (!reward) return undefined;
    const colors = ['#FF6B9D', '#FEC84B', '#12B76A', '#14B8A6', '#7C3AED', '#F97316'];
    const timers = [];
    for (let i = 0; i < 90; i++) {
      const timer = setTimeout(() => {
        const confetti = document.createElement('div');
        const size = 6 + Math.random() * 9;
        confetti.className = 'confetti';
        confetti.style.left = Math.random() * 100 + '%';
        confetti.style.top = '-14px';
        confetti.style.width = `${size}px`;
        confetti.style.height = `${size * (0.55 + Math.random() * 0.7)}px`;
        confetti.style.borderRadius = Math.random() > 0.5 ? '999px' : '2px';
        confetti.style.background = colors[Math.floor(Math.random() * colors.length)];
        confetti.style.animationDuration = `${2.7 + Math.random() * 1.5}s`;
        document.body.appendChild(confetti);
        setTimeout(() => confetti.remove(), 4500);
      }, i * 18);
      timers.push(timer);
    }
    return () => timers.forEach(timer => clearTimeout(timer));
  }, [reward?.id]);
  if (!reward) return null;
  return React.createElement(ModalOverlay, {
    className: "reward-overlay",
    onClick: onClose,
    role: "dialog",
    "aria-modal": "true",
    "aria-label": "Nagroda zdobyta"
  }, React.createElement("div", {
    className: "reward-overlay-content",
    onClick: e => e.stopPropagation()
  }, React.createElement("div", {
    className: "reward-overlay-inner"
  }, React.createElement("div", {
    className: "reward-kicker"
  }, "Wielkie osiągnięcie"), React.createElement("div", {
    className: "reward-medal",
    "aria-hidden": "true"
  }, "\uD83C\uDFC6"), React.createElement("h2", {
    className: "reward-title"
  }, "Nagroda zdobyta!"), React.createElement("div", {
    className: "reward-name"
  }, reward.title), reward.description && React.createElement("p", {
    className: "reward-description"
  }, reward.description), React.createElement("div", {
    className: "reward-fanfare",
    "aria-hidden": "true"
  }, React.createElement("span", null, "\uD83C\uDFBA Fanfarowy moment"), React.createElement("span", null, "\u2728 Nowy sukces"), React.createElement("span", null, "\uD83C\uDF81 Nagroda czeka")), React.createElement("p", {
    className: "reward-description"
  }, "Rodzic widzi ją teraz na liście nagród do wydania."), React.createElement("button", {
    className: "btn btn-primary",
    onClick: onClose
  }, "Świętujemy!"))));
};

export default RewardOverlay;
