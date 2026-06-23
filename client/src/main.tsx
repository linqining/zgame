import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import logoWithText from './assets/img/logo_with_text.svg';
import Providers from './context/Providers';
import { logger } from './helpers/logger';
import { initSuiServices } from './sui/config';

// Initialize zkLogin session manager + sponsored transaction service before
// React renders. These services must be ready before any wallet connects or
// any zkLogin callback is processed (e.g. /auth/callback).
initSuiServices();

// Capture OAuth id_token from URL hash BEFORE React renders.
// Google OAuth implicit flow returns id_token in hash fragment (#id_token=xxx).
// Some browsers/routers may strip the hash before React components can read it.
(function captureOAuthCallback() {
  logger.log('[OAuth] Page loaded, full URL:', window.location.href);
  logger.log('[OAuth] Hash:', window.location.hash);
  logger.log('[OAuth] Search:', window.location.search);
  logger.log('[OAuth] Pathname:', window.location.pathname);

  const hash = window.location.hash;
  if (hash) {
    const params = new URLSearchParams(hash.slice(1));
    const idToken = params.get('id_token');
    const error = params.get('error');
    if (idToken) {
      sessionStorage.setItem('oauth_id_token', idToken);
      logger.log('[OAuth] Captured id_token from hash');
    } else {
      logger.log('[OAuth] Hash exists but no id_token found. Hash params:', Object.fromEntries(params));
    }
    if (error) {
      sessionStorage.setItem('oauth_error', error);
      const errorDesc = params.get('error_description');
      if (errorDesc) sessionStorage.setItem('oauth_error_desc', errorDesc);
    }
  } else {
    logger.log('[OAuth] No hash fragment in URL');
  }
  // Also check search params (some providers use query string)
  const search = window.location.search;
  if (search) {
    const params = new URLSearchParams(search);
    const idToken = params.get('id_token');
    if (idToken && !sessionStorage.getItem('oauth_id_token')) {
      sessionStorage.setItem('oauth_id_token', idToken);
      logger.log('[OAuth] Captured id_token from search params');
    }
  }
})();

const rootElement = document.getElementById('root');
const cookieBannerRoot = document.getElementById('cookie-banner');
const loadingScreen = document.getElementById('loading-screen');

if (
  import.meta.env.PROD &&
  import.meta.env.VITE_MAINTENANCE_MODE === 'true'
) {
  const template = `
    <div style="width: 100%; padding: 0 1.5rem; min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; overflow: hidden; background-color: #ffffff;">
      <img style="width: 100%; max-width: 320px;" src=${logoWithText} alt="Secret Poker">
      <p style="font-size: 1.5rem; font-family: 'Inter', sans-serif; color: #475569; text-align: center; margin-top: 3rem; padding: 1rem 2rem; background: rgba(241, 245, 249, 0.9); border: 1px solid rgba(226, 232, 240, 0.9); border-radius: 1rem;">The website is currently in maintenance mode.</p>
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
