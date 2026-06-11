import React, { useContext } from 'react';
import LogoWithText from '../logo/LogoWithText';
import Logo from '../logo/LogoIcon';
import Container from '../layout/Container';
import styled from 'styled-components';
import { Link } from 'react-router-dom';
import Hider from '../layout/Hider';
import Button from '../buttons/Button';
import HamburgerButton from '../buttons/HamburgerButton';
import Spacer from '../layout/Spacer';
import Text from '../typography/Text';
import contentContext from '../../context/content/contentContext';
import { ConnectButton } from '@mysten/dapp-kit-react/ui';

interface NavbarProps {
  loggedIn: boolean;
  chipsAmount: number | null;
  openModal: (
    children: () => React.ReactNode,
    headingText: string,
    btnText: string,
    btnCallBack?: () => void,
    onCloseCallBack?: () => void,
  ) => void;
  openNavMenu: () => void;
  className?: string;
  variant?: 'light' | 'dark';
}

const StyledNav = styled.nav`
  padding: 1rem 0;
  position: absolute;
  z-index: 99;
  width: 100%;
  transition: all 0.4s ease;
  background-color: ${(props: any) => props.theme.colors.lightestBg};
  border-bottom: 1px solid rgba(226, 232, 240, 0.9);
`;

const ChipAmount = styled.div`
  color: #b45309;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  font-size: 0.95rem;
  padding: 0.4rem 1rem;
  background: rgba(251, 191, 36, 0.12);
  border: 1px solid rgba(251, 191, 36, 0.25);
  border-radius: 8px;
`;

const StyledButton = styled(Button)`
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: white;
  border: none;
  box-shadow: 0 4px 20px rgba(102, 126, 234, 0.25);
  &:hover {
    transform: translateY(-3px);
    box-shadow: 0 12px 35px rgba(102, 126, 234, 0.45);
  }
`;

const StyledHamburgerButton = styled(HamburgerButton)`
  .hamburger-line {
    background-color: #0f172a;
  }
`;

const Navbar: React.FC<NavbarProps> = ({
  loggedIn,
  chipsAmount,
  openModal,
  openNavMenu,
  className,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;

  const openShopModal = () =>
    openModal(
      () => (
        <Text textAlign="center">
            {getLocalizedString('shop-coming_soon-modal_text')}
          </Text>
      ),
      getLocalizedString('shop-coming_soon-modal_heading'),
      getLocalizedString('shop-coming_soon-modal_btn_text'),
    );

  // 未登录状态
  if (!loggedIn) {
    return (
      <StyledNav className={className}>
        <Container contentCenteredMobile>
          <Link to="/">
            <LogoWithText />
          </Link>
          <Hider hideOnMobile>
            <Spacer>
              <ConnectButton />
            </Spacer>
          </Hider>
        </Container>
      </StyledNav>
    );
  }

  // 已登录状态
  return (
    <StyledNav className={className}>
      <Container>
        <Link to="/">
          <Hider hideOnMobile>
            <LogoWithText />
          </Hider>
          <Hider hideOnDesktop>
            <Logo />
          </Hider>
        </Link>
        <Spacer>
          <ChipAmount>
            ${(chipsAmount ?? 0).toLocaleString()}
          </ChipAmount>
          <ConnectButton />
          <Hider hideOnMobile>
            <StyledButton onClick={openShopModal}>
              {getLocalizedString('navbar-buychips_btn')}
            </StyledButton>
          </Hider>
          <StyledHamburgerButton clickHandler={openNavMenu} />
        </Spacer>
      </Container>
    </StyledNav>
  );
};

export default Navbar;
