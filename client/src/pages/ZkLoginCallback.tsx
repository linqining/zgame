import React, { useEffect, useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import authContext from '../context/auth/authContext';
import styled from 'styled-components';

const CallbackWrapper = styled.div`
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: #f8fafc;
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
  background: white;
  color: #334155;
  cursor: pointer;
  font-size: 0.85rem;

  &:hover {
    background: #f8fafc;
  }
`;

/**
 * OAuth callback page for zkLogin.
 * This page handles the redirect from OAuth providers (Google, Apple, etc.)
 * It extracts the JWT from the URL hash and completes the zkLogin flow.
 */
const ZkLoginCallback: React.FC = () => {
  const { handleZkLoginCallback, isLoggedIn } = useContext(authContext)!;
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState('Processing OAuth callback...');

  useEffect(() => {
    const processCallback = async () => {
      try {
        // Extract JWT - try sessionStorage first (captured in main.tsx before React renders),
        // then fall back to URL hash/search params
        let jwt: string | null = sessionStorage.getItem('oauth_id_token');

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

        // Clean up sessionStorage
        sessionStorage.removeItem('oauth_id_token');
        sessionStorage.removeItem('oauth_error');
        sessionStorage.removeItem('oauth_error_desc');

        if (!jwt) {
          throw new Error('No id_token found in OAuth callback. Please try again.');
        }

        setStatus('Generating ZK proof...');
        await handleZkLoginCallback(jwt);

        setStatus('Login successful! Redirecting...');
        setTimeout(() => navigate('/', { replace: true }), 500);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Unknown error';
        console.error('[ZkLoginCallback] Error:', msg);
        setError(msg);
        setStatus('Login failed');
      }
    };

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
            <RetryButton onClick={() => navigate('/login')}>
              Back to Login
            </RetryButton>
          </>
        )}
      </CallbackCard>
    </CallbackWrapper>
  );
};

export default ZkLoginCallback;
