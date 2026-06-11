import React, { useContext } from 'react';
import styled from 'styled-components';
import CloseButton from '../buttons/CloseButton';
import Button from '../buttons/Button';
import Text from '../typography/Text';
import ColoredText from '../typography/ColoredText';
import ChipsAmount from '../user/ChipsAmount';
import { Link } from 'react-router-dom';
import lobbyIcon from '../../assets/icons/lobby-icon.svg';
import userIcon from '../../assets/icons/user-icon.svg';
import contentContext from '../../context/content/contentContext';
import socketContext from '../../context/websocket/socketContext';
import globalContext from '../../context/global/globalContext';

const NavMenuWrapper = styled.div`
  position: fixed;
  display: flex;
  justify-content: center;
  align-items: center;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 100;
  background-color: rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
`;

const StyledNavMenu = styled.div`
  position: fixed;
  display: flex;
  flex-direction: column;
  top: 0;
  right: 0;
  width: 320px;
  height: 100%;
  background: rgba(255, 255, 255, 0.95);
  border-left: 1px solid rgba(226, 232, 240, 0.9);
  box-shadow: -8px 0 40px rgba(0, 0, 0, 0.08);
  overflow: hidden;

  @media screen and (max-width: 400px) {
    width: 85vw;
  }
`;

const MenuHeader = styled.div`
  padding: 1rem 1.25rem 0;
  justify-self: flex-start;
`;

const MenuItem = styled(Link)`
  display: flex;
  padding: 0.85rem 1.25rem;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  text-align: right;
  font-family: 'Inter', -apple-system, sans-serif;
  color: #0f172a !important;
  border-bottom: 1px solid rgba(226, 232, 240, 0.6);
  background-color: transparent !important;
  font-size: 0.95rem;
  font-weight: 500;
  text-decoration: none;
  transition: all 0.2s ease;

  img {
    opacity: 0.6;
    transition: opacity 0.2s ease;
  }

  &:hover {
    background-color: rgba(102, 126, 234, 0.08) !important;
    color: #667eea !important;

    img {
      opacity: 1;
    }
  }

  &:focus {
    outline: none;
    border-left: 3px solid #667eea;
  }
`;

const MenuBody = styled.div`
  overflow-y: auto;
  margin-top: 0.5rem;

  &::-webkit-scrollbar {
    width: 0.4rem;
  }

  &::-webkit-scrollbar-track {
    background: transparent;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(203, 213, 225, 0.6);
    border-radius: 4px;
  }
`;

const MenuFooter = styled.div`
  padding: 1rem 1.25rem;
  margin: auto 0 0 0;
  border-top: 1px solid rgba(226, 232, 240, 0.6);
`;

const HorizontalWrapper = styled.div`
  display: flex;
  margin: 1.5rem auto;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;

  ${Button} {
    min-width: 6.5rem;
    background: linear-gradient(135deg, #667eea, #764ba2) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    box-shadow: 0 2px 12px rgba(102, 126, 234, 0.2) !important;
  }
`;

const SalutationText = styled(Text)`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.25rem;
  font-weight: 700;
  color: #0f172a;
  letter-spacing: -0.02em;

  ${ColoredText} {
    background: linear-gradient(135deg, #667eea, #764ba2);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
`;

const OnlineText = styled(Text)`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 0.85rem;
  color: #64748b;
  margin-top: 0.25rem;

  ${ColoredText} {
    color: #10b981;
    font-weight: 600;
  }
`;

const IconWrapper = styled.div`
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;

  button {
    color: #64748b !important;

    &:hover {
      color: #0f172a !important;
    }
  }
`;

const LogoutButton = styled(Button)`
  background: rgba(241, 245, 249, 0.8) !important;
  color: #475569 !important;
  border: 1px solid rgba(226, 232, 240, 0.8) !important;
  border-radius: 10px !important;
  font-weight: 500 !important;
  transition: all 0.25s ease !important;

  &:hover {
    border-color: rgba(239, 68, 68, 0.4) !important;
    color: #ef4444 !important;
    background: rgba(239, 68, 68, 0.06) !important;
  }
`;

interface NavMenuProps {
  onClose: () => void;
  logout: () => void;
  userName: string | null;
  chipsAmount: number | null;
  lang?: string;
  setLang?: React.Dispatch<React.SetStateAction<string>>;
  openModal: (
    children: () => React.ReactNode,
    headingText: string,
    btnText: string,
    btnCallBack?: () => void,
    onCloseCallBack?: () => void,
  ) => void;
}

const NavMenu: React.FC<NavMenuProps> = ({
  onClose,
  logout,
  userName,
  chipsAmount,
  openModal,
}) => {
  const { players } = useContext(globalContext)!;
  const { getLocalizedString } = useContext(contentContext)!;
  const { cleanUp } = useContext(socketContext)!;

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

  return (
    <NavMenuWrapper
      id="wrapper"
      onClick={(e) => {
        if ((e.target as HTMLElement).id === 'wrapper') {
          onClose();
        }
      }}
    >
      <StyledNavMenu>
        <IconWrapper>
          <CloseButton clickHandler={onClose} autoFocus />
        </IconWrapper>
        <MenuHeader>
          <SalutationText textAlign="left">
            {getLocalizedString('main_page-salutation')}
            <br />
            <ColoredText>{userName}!</ColoredText>
          </SalutationText>
          {players && (
            <OnlineText textAlign="left">
              {getLocalizedString('game_online-lbl')} <ColoredText>{players.length}</ColoredText>
            </OnlineText>
          )}
          <HorizontalWrapper>
            <ChipsAmount
              chipsAmount={chipsAmount ?? 0}
              clickHandler={openShopModal}
            />
            <Button onClick={openShopModal} small primary>
              {getLocalizedString('shop-coming_soon-modal_heading')}
            </Button>
          </HorizontalWrapper>
        </MenuHeader>
        <MenuBody>
          <MenuItem
            to="/"
            onClick={() => {
              onClose();
            }}
          >
            {getLocalizedString('navmenu-menu_item-lobby_txt')}
            <img
              src={lobbyIcon}
              alt="Lobby"
              width="22"
              style={{ width: '22px' }}
            />
          </MenuItem>
          <MenuItem
            to="/dashboard"
            onClick={() => {
              onClose();
            }}
          >
            {getLocalizedString('navmenu-menu_item-dashboard_txt')}
            <img
              src={userIcon}
              alt="Dashboard"
              width="22"
              style={{ width: '22px' }}
            />
          </MenuItem>

        </MenuBody>
        <MenuFooter>
          <LogoutButton
            onClick={() => {
              cleanUp();
              logout();
              onClose();
            }}
            secondary
            fullWidth
            small
          >
            {getLocalizedString('navmenu-logout_btn')}
          </LogoutButton>
        </MenuFooter>
      </StyledNavMenu>
    </NavMenuWrapper>
  );
};

export default NavMenu;
