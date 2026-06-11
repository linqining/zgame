import React, { useContext, useEffect, useCallback } from 'react';
import Axios from 'axios';
import MainLayout from './layouts/_MainLayout';
import LoadingScreen from './components/loading/LoadingScreen';
import globalContext, { useGlobalContext } from './context/global/globalContext';
import Routes from './components/routing/Routes';
import contentContext, { useContentContext } from './context/content/contentContext';
import Text from './components/typography/Text';
import modalContext, { useModalContext } from './context/modal/modalContext';
import config from './clientConfig';
import GoogleAnalytics from './components/analytics/GoogleAnalytics';
import { PlayerProvider } from './context/player/SecretPokerPlayerContext';

const AppInner: React.FC = () => {
  const { isLoading, chipsAmount, setChipsAmount, setIsLoading } = useGlobalContext();
  const { getLocalizedString } = useContentContext();
  const { openModal, closeModal } = useModalContext();
  const { isLoading: contentIsLoading } = useContentContext();

  const handleFreeChipsRequest = useCallback(async () => {
    setIsLoading(true);

    try {
      const token = localStorage.getItem('token');

      const res = await Axios.get('/api/chips/free', {
        headers: {
          'x-auth-token': token,
        },
      });

      const { chipsAmount } = res.data;

      setChipsAmount(chipsAmount);
    } catch (error) {
      // alert(error);
      console.error(error);
    } finally {
      closeModal();
    }

    setIsLoading(false);
  }, [setIsLoading, setChipsAmount, closeModal]);

  const showFreeChipsModal = useCallback(() => {
    openModal(
      () => (
        <Text textAlign="center">
          {getLocalizedString('global_get-free-chips-modal_content')}
        </Text>
      ),
      getLocalizedString('global_get-free-chips-modal_header'),
      getLocalizedString('global_get-free-chips-modal_btn-txt'),
      handleFreeChipsRequest,
    );
  }, [openModal, getLocalizedString, handleFreeChipsRequest]);

  useEffect(() => {
    if (
      chipsAmount !== null &&
      chipsAmount < 1000 &&
      !isLoading &&
      !contentIsLoading
    ) {
      const timer = setTimeout(showFreeChipsModal, 2000);
      return () => clearTimeout(timer);
    }
  }, [chipsAmount, isLoading, contentIsLoading, showFreeChipsModal]);

  return (
    <>
      {isLoading || contentIsLoading ? (
        <LoadingScreen />
      ) : (
        <MainLayout>
          <Routes />
        </MainLayout>
      )}
      {config.isProduction && <GoogleAnalytics />}
    </>
  );
};

const App: React.FC = () => {
  return (
    <PlayerProvider>
      <AppInner />
    </PlayerProvider>
  );
};

export default App;
