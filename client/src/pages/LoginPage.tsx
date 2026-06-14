import React, { useContext, useMemo } from 'react';
import { Navigate } from 'react-router-dom';
import useScrollToTopOnPageLoad from '../hooks/useScrollToTopOnPageLoad';
import authContext from '../context/auth/authContext';
import { TiledBackgroundImage } from '../components/decoration/TiledBackgroundImage';
import { ConnectButton } from '@mysten/dapp-kit-react/ui';
import { ZKLOGIN_CONFIG } from '../sui/config';
import LogoWithText from '../components/logo/LogoWithText';
import suiLogoSvg from '../assets/img/logo-icon.svg';
import styled from 'styled-components';

const PageWrapper = styled.div`
  min-height: 100vh;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  position: relative;
  overflow: hidden;
  padding: 6rem 2rem 3rem;
  background-color: #f8fafc;
`;

const LoginCard = styled.div`
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 420px;
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 20px;
  padding: 2.5rem 2rem;
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
`;

const LogoWrapper = styled.div`
  display: flex;
  justify-content: center;
  margin-bottom: 2rem;
`;

const FormTitle = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.5rem;
  font-weight: 700;
  text-align: center;
  color: #0f172a;
  margin-bottom: 1.5rem;
  letter-spacing: -0.02em;
`;

const WalletSection = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 1.25rem;
  padding: 1.5rem 1.25rem;
  border-radius: 16px;
  background: rgba(241, 245, 249, 0.6);
  border: 1.5px dashed rgba(77, 162, 255, 0.25);
  gap: 0.5rem;
  transition: all 0.3s ease;

  &:hover {
    border-color: rgba(77, 162, 255, 0.45);
    background: rgba(241, 245, 249, 0.8);
  }
`;

const SuiLogoWrapper = styled.div`
  width: 48px;
  height: 48px;
  border-radius: 14px;
  background: linear-gradient(135deg, rgba(98, 151, 181, 0.1), rgba(77, 162, 255, 0.08));
  border: 1px solid rgba(98, 151, 181, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 0.5rem;

  img {
    width: 32px;
    height: 32px;
  }
`;

const WalletTitle = styled.div`
  font-size: 0.95rem;
  font-weight: 600;
  color: #0f172a;
  text-align: center;
`;

const WalletDesc = styled.div`
  font-size: 0.78rem;
  color: #64748b;
  text-align: center;
  margin-bottom: 0.5rem;
`;

const Divider = styled.div`
  display: flex;
  align-items: center;
  margin: 1.25rem 0;
  gap: 0.75rem;

  &::before, &::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(226, 232, 240, 0.9);
  }

  span {
    font-size: 0.78rem;
    color: #94a3b8;
    white-space: nowrap;
  }
`;

const OAuthSection = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.625rem;
`;

const OAuthButton = styled.button<{ $provider: string }>`
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.7rem 1rem;
  border-radius: 10px;
  border: 1px solid rgba(226, 232, 240, 0.9);
  background: white;
  font-size: 0.875rem;
  font-weight: 500;
  color: #334155;
  cursor: pointer;
  transition: all 0.2s ease;

  &:hover {
    background: #f8fafc;
    border-color: #cbd5e1;
  }

  &:active {
    transform: scale(0.98);
  }
`;

const OAuthNote = styled.div`
  font-size: 0.72rem;
  color: #94a3b8;
  text-align: center;
  margin-top: 0.5rem;
  line-height: 1.4;
`;

const LoginPage: React.FC = () => {
  const { isLoggedIn, loginWithZkLogin } = useContext(authContext)!;

  useScrollToTopOnPageLoad();

  // Only show OAuth buttons for providers with configured client IDs
  const availableProviders = useMemo(() => {
    const providers: { key: string; label: string; icon: React.ReactNode }[] = [];
    if (ZKLOGIN_CONFIG.google.clientId) {
      providers.push({
        key: 'google',
        label: 'Sign in with Google',
        icon: <svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>,
      });
    }
    if (ZKLOGIN_CONFIG.apple.clientId) {
      providers.push({
        key: 'apple',
        label: 'Sign in with Apple',
        icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/></svg>,
      });
    }
    if (ZKLOGIN_CONFIG.twitch.clientId) {
      providers.push({
        key: 'twitch',
        label: 'Sign in with Twitch',
        icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="#9146FF"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>,
      });
    }
    if (ZKLOGIN_CONFIG.facebook.clientId) {
      providers.push({
        key: 'facebook',
        label: 'Sign in with Facebook',
        icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="#1877F2"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>,
      });
    }
    return providers;
  }, []);

  if (isLoggedIn) return <Navigate to="/" />;

  return (
    <PageWrapper>
      <TiledBackgroundImage />
      <LoginCard>
        <LogoWrapper>
          <LogoWithText />
        </LogoWrapper>
        <FormTitle>Sign in to Play</FormTitle>

        <WalletSection>
          <SuiLogoWrapper>
            <img src={suiLogoSvg} alt="Sui" />
          </SuiLogoWrapper>
          <WalletTitle>Sign in with Sui Wallet</WalletTitle>
          <WalletDesc>Connect your wallet to play</WalletDesc>
          <ConnectButton />
        </WalletSection>

        {availableProviders.length > 0 && (
          <>
            <Divider>
              <span>or sign in with</span>
            </Divider>

            <OAuthSection>
              {availableProviders.map((p) => (
                <OAuthButton key={p.key} $provider={p.key} onClick={() => loginWithZkLogin(p.key)}>
                  {p.icon}
                  {p.label}
                </OAuthButton>
              ))}
            </OAuthSection>

            <OAuthNote>
              Social login uses zkLogin — no wallet extension needed.
              Your Sui address is derived from your OAuth account securely.
            </OAuthNote>
          </>
        )}
      </LoginCard>
    </PageWrapper>
  );
};

export default LoginPage;
