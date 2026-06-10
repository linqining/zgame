import React, { useContext } from 'react';
import { useLocation } from 'react-router-dom';
import Navbar from '../components/navigation/Navbar';
import Footer from '../components/navigation/Footer';
import WatermarkWrapper from '../components/decoration/WatermarkWrapper';
import NavMenu from '../components/navigation/NavMenu';
import CookieBanner from '../components/cookies/CookieBanner';
import useNavMenu from '../hooks/useNavMenu';
import useCookie from '../hooks/useCookie';
import { useGlobalContext } from '../context/global/globalContext';
import authContext from '../context/auth/authContext';
import { useLocaContext } from '../context/localization/locaContext';
import { useContentContext } from '../context/content/contentContext';
import { useModalContext } from '../context/modal/modalContext';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const { chipsAmount, userName } = useGlobalContext();
  const { isLoggedIn, logout } = useContext(authContext)!;
  const { lang, setLang } = useLocaContext();
  const { staticPages } = useContentContext();
  const { openModal } = useModalContext();

  const [showNavMenu, openNavMenu, closeNavMenu] = useNavMenu();
  const [isCookieSet, setCookie] = useCookie('cookies-accepted', true);

  const location = useLocation();

  return (
    <div id="layout-wrapper">
      {!location.pathname.includes('/play') && (
        <Navbar
          chipsAmount={chipsAmount}
          loggedIn={isLoggedIn}
          openModal={openModal}
          openNavMenu={openNavMenu}
          className="blur-target"
        />
      )}
      {showNavMenu && (
        <NavMenu
          onClose={closeNavMenu}
          userName={userName}
          logout={logout}
          chipsAmount={chipsAmount}
          lang={lang}
          setLang={setLang}
          openModal={openModal}
        />
      )}
      <main className="blur-target">{children}</main>
      <WatermarkWrapper className="blur-target" />
      {!location.pathname.includes('/play') && (
        <Footer
          className="blur-target"
          setLang={setLang}
          staticPages={staticPages}
        />
      )}
      {!isCookieSet && (
        <CookieBanner clickHandler={() => setCookie('1', 365)} />
      )}
    </div>
  );
};

export default MainLayout;
