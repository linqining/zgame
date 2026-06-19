import React from 'react';
import styled, { keyframes } from 'styled-components';

const spin = keyframes`
  0% { transform: rotateY(0deg); }
  100% { transform: rotateY(360deg); }
`;

const float = keyframes`
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-10px); }
`;

const pulse = keyframes`
  0%, 100% { opacity: 0.6; }
  50% { opacity: 1; }
`;

const Wrapper = styled.div`
  perspective: 1000px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
`;

const CardContainer = styled.div`
  position: relative;
  width: 80px;
  height: 112px;
  transform-style: preserve-3d;
  animation: ${spin} 2s ease-in-out infinite;
`;

const Card = styled.div`
  position: absolute;
  width: 100%;
  height: 100%;
  background: linear-gradient(145deg, #1a1f35, #0d1422);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 3rem;
  box-shadow:
    0 10px 40px rgba(0, 0, 0, 0.5),
    0 0 60px rgba(102, 126, 234, 0.15),
    inset 0 1px 0 rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(102, 126, 234, 0.2);
  backface-visibility: hidden;

  &::before {
    content: '';
    position: absolute;
    inset: 8px;
    border: 1px solid rgba(102, 126, 234, 0.1);
    border-radius: 6px;
  }

  &::after {
    content: '🃏';
    font-size: 3.5rem;
    filter: drop-shadow(0 2px 8px rgba(102, 126, 234, 0.3));
  }
`;

const GlowRing = styled.div`
  position: absolute;
  width: 120px;
  height: 120px;
  border-radius: 50%;
  border: 2px solid transparent;
  background:
    linear-gradient(${({ theme }) => theme.colors.fontColorLight}, ${({ theme }) => theme.colors.fontColorLight}) padding-box,
    /* TODO: #764ba2, #06b6d4 提取到 theme */
    linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2, #06b6d4) border-box;
  opacity: 0.4;
  animation: ${pulse} 2s ease-in-out infinite;
`;

const LogoText = styled.div`
  margin-top: 2.5rem;
  font-size: 1.5rem;
  font-weight: 700;
  /* TODO: #764ba2 提取到 theme */
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  animation: ${float} 3s ease-in-out infinite;
  letter-spacing: 0.05em;
`;

const Tagline = styled.div`
  margin-top: 0.5rem;
  font-size: 0.8rem;
  color: #64748b;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  animation: ${pulse} 3s ease-in-out infinite;
`;

const Loader: React.FC = () => (
  <Wrapper>
    <GlowRing />
    <CardContainer>
      <Card />
    </CardContainer>
    <LogoText>Secret Poker</LogoText>
    <Tagline>Loading...</Tagline>
  </Wrapper>
);

export default Loader;
