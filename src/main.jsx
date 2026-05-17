import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './styles.css';

createRoot(document.getElementById('root')).render(React.createElement(App));

let deferredInstallPrompt = null;
const installButton = document.getElementById('install-app-btn');
const hideInstallButton = () => {
  installButton.style.display = 'none';
  installButton.disabled = false;
};
const showInstallButton = () => {
  installButton.style.display = 'block';
};
installButton.addEventListener('click', async () => {
  if (!deferredInstallPrompt) return;
  installButton.disabled = true;
  deferredInstallPrompt.prompt();
  const choiceResult = await deferredInstallPrompt.userChoice;
  if (choiceResult.outcome !== 'accepted') {
    installButton.disabled = false;
  }
  deferredInstallPrompt = null;
  hideInstallButton();
});
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  deferredInstallPrompt = event;
  showInstallButton();
});
window.addEventListener('appinstalled', () => {
  deferredInstallPrompt = null;
  hideInstallButton();
});
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.getRegistrations().then(registrations => {
      registrations.forEach(registration => registration.unregister());
    }).catch(err => {
      console.warn('Service worker cleanup failed:', err);
    });
  });
}
console.log('🏆 FamilyQuest - Pełna wersja produkcyjna');
console.log('✨ Funkcje: konto rodzica, Postgres, zarządzanie dziećmi i zadaniami, passa, punkty, ranking, nagrody');
