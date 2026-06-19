import React, { useContext } from 'react';
import { Routes, Route } from 'react-router-dom';
import Dashboard from '../../pages/Dashboard';
import SecretPokerHomePage from '../../pages/SecretPokerHomePage';
import Play from '../../pages/Play';
import ProtectedRoute from './ProtectedRoute';
import StaticPage from '../../pages/StaticPage';
import NotFoundPage from '../../pages/NotFoundPage';
import contentContext from '../../context/content/contentContext';
import SecretPokerLobby from '../../pages/SecretPokerLobby';
import SecretPokerGameTable from '../../pages/SecretPokerGameTable';
import ZkLoginCallback from '../../pages/ZkLoginCallback';

const RoutesComponent: React.FC = () => {
  const { staticPages } = useContext(contentContext)!;

  return (
    <Routes>
      <Route path="/" element={<SecretPokerHomePage />} />
      <Route path="/auth/callback" element={<ZkLoginCallback />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />
      {staticPages &&
        staticPages.map((page) => (
          <Route
            key={page.slug}
            path={`/${page.slug}`}
            element={<StaticPage title={page.title} content={page.content} />}
          />
        ))}
      <Route
        path="/play"
        element={
          <ProtectedRoute>
            <Play />
          </ProtectedRoute>
        }
      />
      <Route path="/lobby" element={<SecretPokerLobby />} />
      <Route path="/game/:gameId" element={<SecretPokerGameTable />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
};

export default RoutesComponent;
