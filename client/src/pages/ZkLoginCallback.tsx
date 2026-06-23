import React, { useEffect, useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import authContext from '../context/auth/authContext';
import contentContext from '../context/content/contentContext';
import styled from 'styled-components';
import { logger } from '../helpers/logger';

const CallbackWrapper = styled.div`
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: ${({ theme }) => theme.colors.fontColorLight};
`;

const CallbackCard = styled.div`
  text-align: center;
  padding: 2rem;
`;

const Spinner = styled.div`
  width: 40px;
  height: 40px;
  border: 3px solid #e2e8f0;
  border-top: 3px solid #4da2ff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  margin: 0 auto 1rem;

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
`;

const StatusText = styled.div`
  font-size: 0.95rem;
  /* TODO: #475569 提取到 theme */
  color: #475569;
  margin-bottom: 0.5rem;
`;

const ErrorText = styled.div`
  font-size: 0.85rem;
  color: #ef4444;
  margin-top: 1rem;
`;

const RetryButton = styled.button`
  margin-top: 1rem;
  padding: 0.5rem 1.5rem;
  border-radius: 8px;
  border: 1px solid #cbd5e1;
  background: ${({ theme }) => theme.colors.lightestBg};
  color: #334155;
  cursor: pointer;
  font-size: 0.85rem;

  &:hover {
    background: ${({ theme }) => theme.colors.fontColorLight};
  }
`;

/**
 * Module-level flag to prevent React StrictMode from double-processing the
 * OAuth callback. StrictMode invokes effects twice; the first invocation
 * reads and clears sessionStorage, so the second would find nothing and error.
 */
let callbackProcessed = false;

/**
 * OAuth callback page for zkLogin.
 * This page handles the redirect from OAuth providers (Google, Apple, etc.)
 * It extracts the JWT from the URL hash and completes the zkLogin flow.
 */
const ZkLoginCallback: React.FC = () => {
  const { handleZkLoginCallback, isLoggedIn } = useContext(authContext)!;
  const { getLocalizedString: t } = useContext(contentContext)!;
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState(t('zklogin_processing'));

  useEffect(() => {
    // Guard against React StrictMode double-invoking effects.
    // The first invocation reads and clears sessionStorage; the second
    // would find it empty and throw. Use a module-level flag to prevent
    // the second invocation from running.
    if (callbackProcessed) return;
    callbackProcessed = true;

    const processCallback = async () => {
      try {
        // Extract JWT - try multiple sources:
        // 1. sessionStorage (captured in main.tsx before React renders)
        // 2. URL hash fragment (Google implicit flow: #id_token=xxx)
        // 3. URL search params (some providers use query string)
        let jwt: string | null = sessionStorage.getItem('oauth_id_token');

        if (!jwt && window.location.hash) {
          const hashParams = new URLSearchParams(window.location.hash.slice(1));
          jwt = hashParams.get('id_token');
          if (jwt) logger.log('[ZkLoginCallback] Found id_token in URL hash');
        }

        if (!jwt && window.location.search) {
          const searchParams = new URLSearchParams(window.location.search);
          jwt = searchParams.get('id_token');
          if (jwt) logger.log('[ZkLoginCallback] Found id_token in URL search params');
        }

        logger.log('[ZkLoginCallback] processCallback started, jwt exists:', !!jwt);

        // Check for OAuth error
        const oauthError = sessionStorage.getItem('oauth_error')
          || new URLSearchParams(window.location.hash.slice(1)).get('error')
          || new URLSearchParams(window.location.search).get('error');

        if (oauthError) {
          const errorDesc = sessionStorage.getItem('oauth_error_desc')
            || new URLSearchParams(window.location.hash.slice(1)).get('error_description')
            || new URLSearchParams(window.location.search).get('error_description')
            || oauthError;
          throw new Error(`OAuth error: ${decodeURIComponent(errorDesc)}`);
        }

        // Clean up sessionStorage AFTER reading all values
        sessionStorage.removeItem('oauth_id_token');
        sessionStorage.removeItem('oauth_error');
        sessionStorage.removeItem('oauth_error_desc');

        if (!jwt) {
          throw new Error('No id_token found in OAuth callback. Please try again.');
        }

        setStatus(t('zklogin_generating-proof'));
        await handleZkLoginCallback(jwt);

        setStatus(t('zklogin_success'));
        setTimeout(() => navigate('/', { replace: true }), 500);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Unknown error';
        logger.error('[ZkLoginCallback] Error:', msg);
        setError(msg);
        setStatus(t('zklogin_failed'));
        callbackProcessed = false; // Allow retry on error
      }
    };

    logger.log('[ZkLoginCallback] useEffect fired, isLoggedIn:', isLoggedIn);
    if (!isLoggedIn) {
      processCallback();
    } else {
      navigate('/', { replace: true });
    }
  }, [handleZkLoginCallback, isLoggedIn, navigate]);

  return (
    <CallbackWrapper>
      <CallbackCard>
        {!error ? (
          <>
            <Spinner />
            <StatusText>{status}</StatusText>
          </>
        ) : (
          <>
            <StatusText>{status}</StatusText>
            <ErrorText>{error}</ErrorText>
            <RetryButton onClick={() => navigate('/')}>
              {t('zklogin_back-login')}
            </RetryButton>
          </>
        )}
      </CallbackCard>
    </CallbackWrapper>
  );
};

export default ZkLoginCallback;
