import styled, { keyframes, css } from 'styled-components';
import { motion } from 'framer-motion';

/* ===== Keyframes ===== */

const particleFloat = keyframes`
  0% { transform: translateY(100vh); opacity: 0; }
  10% { opacity: 1; }
  90% { opacity: 1; }
  100% { transform: translateY(-10vh); opacity: 0; }
`;

const orbFloat = keyframes`
  0%, 100% { transform: translate(0, 0); }
  50% { transform: translate(30px, -20px); }
`;

const gradientShift = keyframes`
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
`;

/* ===== Particles ===== */

export const Particles = styled.div`
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  overflow: hidden;
`;

export const Particle = styled.div`
  position: absolute;
  width: 2px;
  height: 2px;
  background: rgba(102, 126, 234, 0.12);
  border-radius: 50%;
  animation: ${particleFloat} linear infinite;
`;

/* ===== Buttons ===== */

export const BtnPrimary = styled(motion.button)<{ $lg?: boolean }>`
  background: linear-gradient(135deg, ${(props) => props.theme.colors.secondaryCta}, #764ba2);
  color: ${(props) => props.theme.colors.lightestBg};
  border: none;
  padding: 0.65rem 1.6rem;
  border-radius: 10px;
  font-weight: 500;
  font-size: 0.9rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  transition: all 0.35s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 2px 12px rgba(102, 126, 234, 0.2);

  &:hover:not(:disabled) {
    box-shadow: 0 6px 24px rgba(102, 126, 234, 0.35);
  }
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  ${(props) =>
    props.$lg &&
    css`
      padding: 0.85rem 2rem;
      font-size: 0.95rem;
    `}
`;

export const BtnSecondary = styled(motion.button)<{ $lg?: boolean }>`
  background: transparent;
  /* TODO: #475569 提取到 theme */
  color: #475569;
  border: 1px solid rgba(148, 163, 184, 0.35);
  padding: 0.65rem 1.6rem;
  border-radius: 10px;
  font-weight: 400;
  font-size: 0.9rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  transition: all 0.35s cubic-bezier(0.22, 1, 0.36, 1);

  &:hover:not(:disabled) {
    border-color: rgba(148, 163, 184, 0.6);
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  ${(props) =>
    props.$lg &&
    css`
      padding: 0.85rem 2rem;
      font-size: 0.95rem;
    `}
`;

/* ===== Home ===== */

export const Home = styled.div`
  height: 100vh;
  overflow-x: hidden;
  overflow-y: auto;
  position: relative;
  background: ${(props) => props.theme.colors.lightestBg};
  color: ${(props) => props.theme.colors.fontColorDark};
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  scroll-snap-type: y mandatory;
  scroll-behavior: smooth;
`;

/* ===== Hero ===== */

export const Hero = styled.section`
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  padding: 5rem 2rem 2rem;
  scroll-margin-top: 5rem;
  scroll-snap-align: start;

  @media (max-width: 768px) {
    padding: 1.5rem;
    padding-top: 7rem;
    padding-bottom: 4rem;
  }
`;

export const HeroBg = styled.div`
  position: absolute;
  inset: 0;
`;

export const HeroGradient = styled.div`
  position: absolute;
  inset: 0;
  background:
    radial-gradient(circle at 20% 50%, rgba(102, 126, 234, 0.06) 0%, transparent 50%),
    radial-gradient(circle at 80% 50%, rgba(118, 75, 162, 0.04) 0%, transparent 50%);
`;

export const HeroOrb = styled.div<{ $variant: 1 | 2 }>`
  position: absolute;
  border-radius: 50%;
  filter: blur(120px);
  opacity: 0.25;
  animation: ${orbFloat} 12s ease-in-out infinite;

  ${(props) =>
    props.$variant === 1 &&
    css`
      width: 500px;
      height: 500px;
      background: rgba(102, 126, 234, 0.15);
      top: 10%;
      left: 10%;
    `}
  ${(props) =>
    props.$variant === 2 &&
    css`
      width: 400px;
      height: 400px;
      background: rgba(118, 75, 162, 0.1);
      bottom: 20%;
      right: 15%;
      animation-delay: -6s;
    `}
`;

export const HeroContent = styled(motion.div)`
  position: relative;
  max-width: 800px;
  text-align: center;
  z-index: 1;
  padding-top: 2rem;
`;

export const HeroBadge = styled(motion.div)`
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: rgba(16, 185, 129, 0.06);
  border: 1px solid rgba(16, 185, 129, 0.12);
  /* TODO: #059669 提取到 theme */
  color: #059669;
  padding: 0.5rem 1rem;
  border-radius: 999px;
  font-size: 0.85rem;
  font-weight: 500;
  margin-bottom: 2rem;
  letter-spacing: 0.02em;
`;

export const HeroTitle = styled(motion.h1)`
  font-size: clamp(3.2rem, 7vw, 5.5rem);
  line-height: 1.1;
  font-weight: 700;
  margin-bottom: 1.5rem;
  letter-spacing: -0.03em;

  @media (max-width: 768px) {
    font-size: clamp(2.2rem, 8vw, 3.5rem);
  }
`;

export const GradientText = styled.span`
  /* TODO: #764ba2, #06b6d4 提取到 theme */
  background: linear-gradient(135deg, ${(props) => props.theme.colors.secondaryCta}, #764ba2, #06b6d4);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  background-size: 200% 200%;
  animation: ${gradientShift} 15s ease infinite;
`;

export const HeroDesc = styled(motion.p)`
  font-size: 1.15rem;
  /* TODO: #475569 提取到 theme */
  color: #475569;
  max-width: 520px;
  margin: 0 auto 2.5rem;
  line-height: 1.7;
  font-weight: 400;

  @media (max-width: 768px) {
    font-size: 1rem;
  }
`;

export const HeroActions = styled(motion.div)`
  display: flex;
  gap: 0.75rem;
  justify-content: center;
  flex-wrap: wrap;
  margin-bottom: 4rem;
`;

export const HeroStats = styled(motion.div)`
  display: flex;
  justify-content: center;
  gap: 3.5rem;
  flex-wrap: wrap;

  @media (max-width: 768px) {
    gap: 1.5rem;
  }
`;

export const Stat = styled.div`
  text-align: center;
  padding: 0.5rem 1rem;
`;

export const StatValue = styled.span`
  display: block;
  font-size: 1.2rem;
  font-weight: 600;
  color: ${(props) => props.theme.colors.fontColorDark};
  font-family: 'JetBrains Mono', monospace;
  margin-bottom: 0.3rem;
`;

export const StatLabel = styled.span`
  font-size: 0.7rem;
  /* TODO: #94a3b8 提取到 theme */
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.12em;
`;

export const StatDivider = styled.div`
  width: 1px;
  background: rgba(226, 232, 240, 0.9);
  align-self: stretch;
  margin: 0.5rem 0;

  @media (max-width: 768px) {
    display: none;
  }
`;

/* ===== Sections ===== */

export const Section = styled.section<{ $variant?: 'default' | 'alt' | 'how' | 'cta' }>`
  padding: 5.5rem 2rem 4rem;
  position: relative;
  z-index: 1;
  scroll-margin-top: 5rem;
  scroll-snap-align: start;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;

  ${(props) =>
    props.$variant === 'alt' &&
    css`
      background: ${props.theme.colors.darkBg};
    `}
  ${(props) =>
    props.$variant === 'how' &&
    css`
      background: ${props.theme.colors.lightBg};
    `}
  ${(props) =>
    props.$variant === 'cta' &&
    css`
      background: linear-gradient(180deg, ${props.theme.colors.lightBg} 0%, rgba(102, 126, 234, 0.1) 100%);
    `}

  @media (max-width: 768px) {
    padding: 7rem 1.5rem 5rem;
  }
`;

export const Container = styled.div`
  max-width: 1100px;
  margin: 0 auto;
`;

export const SectionHeader = styled.div`
  text-align: center;
  margin-bottom: 3rem;
`;

export const SectionTag = styled.span`
  display: inline-block;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: none;
  letter-spacing: 0.1em;
  color: ${(props) => props.theme.colors.secondaryCta};
  margin-bottom: 1rem;
  padding: 0.4rem 1.2rem;
  border-radius: 999px;
  background: rgba(102, 126, 234, 0.06);
  border: 1px solid rgba(102, 126, 234, 0.1);
`;

export const SectionTitle = styled.h2`
  font-size: clamp(2rem, 4vw, 3rem);
  font-weight: 700;
  text-align: center;
  margin-bottom: 0.75rem;
  letter-spacing: -0.02em;
  line-height: 1.2;

  @media (max-width: 768px) {
    font-size: clamp(1.6rem, 5vw, 2.2rem);
  }
`;

export const SectionSubtitle = styled.p`
  font-size: 1.05rem;
  /* TODO: #475569 提取到 theme */
  color: #475569;
  max-width: 480px;
  margin: 0 auto;
  line-height: 1.7;
`;

/* ===== Stagger Grid (shared by feature & value grids) ===== */

export const StaggerGrid = styled(motion.div)`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.75rem;

  @media (max-width: 768px) {
    grid-template-columns: 1fr;
  }
`;

/* ===== Features ===== */

export const FeatureIcon = styled.div`
  margin-bottom: 1.25rem;
  transition: transform 0.4s ease;
`;

export const FeatureCard = styled(motion.div)`
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 16px;
  padding: 2rem;
  transition: all 0.4s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);

  &:hover {
    border-color: rgba(102, 126, 234, 0.2);
    background: rgba(255, 255, 255, 1);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
    transform: translateY(-4px);
  }
  &:hover ${FeatureIcon} {
    transform: translateY(-2px);
  }

  h3 {
    font-size: 1.1rem;
    margin-bottom: 0.6rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    /* TODO: #475569 提取到 theme */
    color: #475569;
    font-size: 0.92rem;
    line-height: 1.65;
  }
`;

/* ===== Value Section ===== */

export const ValueHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;
`;

export const ValueIcon = styled.div`
  transition: transform 0.4s ease;
`;

export const ValueCard = styled(motion.div)`
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 16px;
  padding: 1.75rem;
  transition: all 0.4s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);

  &:hover {
    border-color: rgba(102, 126, 234, 0.2);
    background: rgba(255, 255, 255, 1);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
    transform: translateY(-4px);
  }
  &:hover ${ValueIcon} {
    transform: translateY(-2px);
  }

  h3 {
    font-size: 1.1rem;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    /* TODO: #475569 提取到 theme */
    color: #475569;
    font-size: 0.9rem;
    line-height: 1.6;
  }
`;

export const ValueStat = styled.div`
  text-align: right;
`;

export const StatNumber = styled.span`
  display: block;
  font-size: 1.6rem;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
  line-height: 1;
`;

export const StatDesc = styled.span`
  font-size: 0.7rem;
  /* TODO: #94a3b8 提取到 theme */
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 0.3rem;
`;

/* ===== Protocol Flow ===== */

export const ProtocolFlow = styled.div`
  max-width: 640px;
  margin: 0 auto;
`;

export const ProtocolStep = styled.div`
  display: flex;
  align-items: flex-start;
  gap: 1.25rem;
  position: relative;
  padding-bottom: 1.25rem;

  @media (max-width: 768px) {
    gap: 1rem;
    padding-bottom: 1.5rem;
  }
`;

export const StepNumber = styled.div`
  width: 48px;
  height: 48px;
  border-radius: 14px;
  background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
  border: 1px solid rgba(102, 126, 234, 0.15);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  position: relative;
  z-index: 2;
`;

export const StepNum = styled.span`
  position: absolute;
  font-size: 0.6rem;
  font-weight: 600;
  color: ${(props) => props.theme.colors.secondaryCta};
  top: 6px;
  left: 8px;
`;

export const StepIcon = styled.span`
  /* TODO: #64748b 提取到 theme */
  color: #64748b;
`;

export const StepContent = styled.div`
  flex: 1;
  padding-top: 0.25rem;

  h4 {
    font-size: 1.1rem;
    font-weight: 600;
    margin: 0 0 0.4rem;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    /* TODO: #475569 提取到 theme */
    color: #475569;
    font-size: 0.92rem;
    line-height: 1.6;
    margin: 0;
  }
`;

export const StepLine = styled.div`
  position: absolute;
  left: 24px;
  top: 48px;
  bottom: 0;
  width: 1px;
  background: linear-gradient(180deg, rgba(102, 126, 234, 0.2), transparent);
  z-index: 1;
`;

/* ===== CTA Section ===== */

export const CTAContent = styled.div`
  text-align: center;
  max-width: 500px;
  margin: 0 auto;

  h2 {
    font-size: clamp(2rem, 4vw, 3rem);
    font-weight: 700;
    margin-bottom: 0.75rem;
    letter-spacing: -0.02em;
  }
  p {
    /* TODO: #475569 提取到 theme */
    color: #475569;
    font-size: 1rem;
    margin: 0 auto 2rem;
    line-height: 1.7;
  }
`;

/* ===== Footer ===== */

export const Footer = styled.footer`
  border-top: 1px solid rgba(203, 213, 225, 0.8);
  padding: 3rem 2rem;
  background: ${(props) => props.theme.colors.darkBg};
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  position: relative;
  z-index: 1;
  scroll-margin-top: 5rem;
  scroll-snap-align: start;
  min-height: 50vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
`;

export const FooterContent = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1.5rem;
  max-width: 1100px;
  margin: 0 auto;
`;

export const FooterBrand = styled.div`
  span:first-child {
    font-size: 1.2rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    /* TODO: #475569 提取到 theme */
    color: #475569;
    font-size: 0.8rem;
    margin-top: 0.3rem;
  }
`;

export const FooterLinks = styled.div`
  display: flex;
  gap: 0.75rem;
  align-items: center;
`;

export const FooterLink = styled(motion.button)`
  background: transparent;
  /* TODO: #475569 提取到 theme */
  color: #475569;
  border: 1px solid rgba(148, 163, 184, 0.25);
  padding: 0.4rem 1rem;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.25s ease;

  &:hover {
    border-color: rgba(148, 163, 184, 0.45);
    color: ${(props) => props.theme.colors.fontColorDark};
  }
`;

export const FooterTech = styled.div`
  span {
    display: block;
    font-size: 0.75rem;
    /* TODO: #64748b 提取到 theme */
    color: #64748b;
    margin-bottom: 0.4rem;
  }
`;

export const TechTags = styled.div`
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;

  span {
    background: rgba(241, 245, 249, 0.6);
    border: 1px solid rgba(226, 232, 240, 0.8);
    padding: 0.25rem 0.6rem;
    border-radius: 6px;
    font-size: 0.72rem;
    /* TODO: #475569 提取到 theme */
    color: #475569;
    transition: all 0.2s ease;
    cursor: default;

    &:hover {
      border-color: ${(props) => props.theme.colors.secondaryCta};
      color: ${(props) => props.theme.colors.secondaryCta};
    }
  }
`;

export const FooterRef = styled.div`
  span {
    display: block;
    font-size: 0.75rem;
    /* TODO: #64748b 提取到 theme */
    color: #64748b;
    margin-bottom: 0.2rem;
  }
  a {
    color: ${(props) => props.theme.colors.secondaryCta};
    font-size: 0.8rem;
    transition: all 0.2s ease;

    &:hover {
      /* TODO: #06b6d4 提取到 theme */
      color: #06b6d4;
    }
  }
`;

/* ===== Scroll Nav ===== */

export const ScrollNav = styled.nav`
  position: fixed;
  right: 1.5rem;
  top: 50%;
  transform: translateY(-50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  z-index: 50;

  @media (max-width: 768px) {
    display: none;
  }
`;

export const ScrollLabel = styled.span`
  position: absolute;
  right: 1.25rem;
  top: 50%;
  transform: translateY(-50%) translateX(4px);
  white-space: nowrap;
  font-size: 0.7rem;
  font-weight: 500;
  /* TODO: #475569 提取到 theme */
  color: #475569;
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid rgba(226, 232, 240, 0.9);
  padding: 0.25rem 0.6rem;
  border-radius: 6px;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.25s ease, transform 0.25s ease;
`;

export const ScrollDot = styled.button<{ $active?: boolean }>`
  position: relative;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: rgba(102, 126, 234, 0.25);
  border: none;
  cursor: pointer;
  padding: 0;
  transition: all 0.3s ease;

  &:hover ${ScrollLabel} {
    opacity: 1;
    transform: translateY(-50%) translateX(0);
  }

  ${(props) =>
    props.$active &&
    css`
      /* TODO: #764ba2 提取到 theme */
      background: linear-gradient(135deg, ${props.theme.colors.secondaryCta}, #764ba2);
      transform: scale(1.3);
      box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.15);
    `}
`;
