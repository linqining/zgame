import React, { useContext } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import authContext from '../../context/auth/authContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const auth = useContext(authContext);
  const location = useLocation();

  const isLoggedIn = auth?.isLoggedIn;
  const hasWallet = !!auth?.walletAddress;

  if (!isLoggedIn && !hasWallet) {
    return <Navigate to="/" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

export default ProtectedRoute;
