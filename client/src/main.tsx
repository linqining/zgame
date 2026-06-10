import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import logoWithText from './assets/img/logo-text@2x.png';
import Providers from './context/Providers';

const rootElement = document.getElementById('root');
const cookieBannerRoot = document.getElementById('cookie-banner');
const loadingScreen = document.getElementById('loading-screen');

if (
  import.meta.env.PROD &&
  import.meta.env.VITE_MAINTENANCE_MODE === 'true'
) {
  const template = `
    <div style="width: 100%; padding: 0 1.5rem; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; overflow: hidden; background-color: hsl(43, 40%, 86%);">
      <img style="width: 100%; max-width: 320px;" src=${logoWithText} alt="Vintage Poker">
      <p style="font-size: 1.5rem; font-family: 'Roboto', sans-serif; color: hsl(36, 71%, 3%); text-align: center; margin-top: 3rem; padding: 1rem 2rem; background-color: hsl(49, 63%, 92%); border-radius: 2rem;">The website is currently in maintenance mode.</p>
    </div>
  `;
  if (loadingScreen) loadingScreen.style.display = 'none';
  if (rootElement) {
    rootElement.innerHTML = template;
    rootElement.style.display = 'block';
  }
} else {
  if (rootElement) {
    const root = createRoot(rootElement);
    root.render(
      <React.StrictMode>
        <Providers>
          <App />
        </Providers>
      </React.StrictMode>,
    );
  }

  // Hide loading screen and show app content when window has fully loaded
  window.onload = () => {
    setTimeout(() => {
      if (loadingScreen) loadingScreen.style.display = 'none';
      if (rootElement) rootElement.style.display = 'block';
      if (cookieBannerRoot) cookieBannerRoot.style.display = 'block';
    }, 1000);
  };
}
