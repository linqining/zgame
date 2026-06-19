import React from 'react';
import { useLocation } from 'react-router-dom';
import MainLayout from './layouts/_MainLayout';
import LoadingScreen from './components/loading/LoadingScreen';
import { useGlobalContext } from './context/global/globalContext';
import Routes from './components/routing/Routes';
import { useContentContext } from './context/content/contentContext';
import config from './clientConfig';
import GoogleAnalytics from './components/analytics/GoogleAnalytics';

const AppInner: React.FC = () => {
  const { isLoading } = useGlobalContext();
  const { isLoading: contentIsLoading } = useContentContext();

  const location = useLocation();
  // The zkLogin OAuth callback route must render immediately, bypassing the
  // loading screen. If the loading screen blocks Routes from rendering,
  // ZkLoginCallback never mounts and the OAuth callback is never processed.
  const isCallbackRoute = location.pathname === '/auth/callback';
  const showLoading = (isLoading || contentIsLoading) && !isCallbackRoute;

  console.log('[App] render:', { isLoading, contentIsLoading, isCallbackRoute, showLoading, pathname: location.pathname });

  return (
    <>
      {showLoading ? (
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
    <AppInner />
  );
};

export default App;
