import React, { useContext } from 'react';
import { Navigate } from 'react-router-dom';
import useScrollToTopOnPageLoad from '../hooks/useScrollToTopOnPageLoad';
import authContext from '../context/auth/authContext';
import { TiledBackgroundImage } from '../components/decoration/TiledBackgroundImage';
import { ConnectButton } from '@mysten/dapp-kit-react/ui';
import styled from 'styled-components';
import LogoWithText from '../components/logo/LogoWithText';

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


const RegisterCard = styled.div`
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
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: rgba(77, 162, 255, 0.1);
  border: 1px solid rgba(77, 162, 255, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 0.5rem;

  svg {
    width: 24px;
    height: 24px;
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

const RegistrationPage: React.FC = () => {
  const { isLoggedIn } = useContext(authContext)!;

  useScrollToTopOnPageLoad();

  if (isLoggedIn) return <Navigate to="/" />;

  return (
    <PageWrapper>
      <TiledBackgroundImage />
      <RegisterCard>
        <LogoWrapper>
          <LogoWithText />
        </LogoWrapper>
        <FormTitle>Sign in with Sui Wallet</FormTitle>

        <WalletSection>
          <SuiLogoWrapper>
            <svg viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path
                d="M18 2C9.163 2 2 9.163 2 18s7.163 16 16 16 16-7.163 16-16S26.837 2 18 2zm0 29.091c-7.228 0-13.09-5.863-13.09-13.091S10.772 4.909 18 4.909 31.09 10.772 31.09 18 25.228 31.091 18 31.091z"
                fill="#4DA2FF"
                fillOpacity="0.2"
              />
              <path
                d="M26.5 14.5c-1.5-3-5-5-8.5-5s-7 2-8.5 5c-.5 1-.5 2.5 0 3.5 1 2 3 3.5 5 4.5 2 1 4.5 1.5 6.5 1s4-1.5 5-3c1-1.5 1.5-3.5.5-6z"
                stroke="#4DA2FF"
                strokeWidth="2"
                fill="none"
                strokeLinecap="round"
              />
              <circle cx="18" cy="18" r="2" fill="#4DA2FF" />
            </svg>
          </SuiLogoWrapper>
          <WalletTitle>Sign in with Sui Wallet</WalletTitle>
          <WalletDesc>One-click authentication</WalletDesc>
          <ConnectButton />
        </WalletSection>
      </RegisterCard>
    </PageWrapper>
  );
};

export default RegistrationPage;
