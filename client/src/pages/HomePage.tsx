import React, { useContext } from 'react';
import Landing from './Landing';
import MainPage from './MainPage';
import authContext from '../context/auth/authContext';

const HomePage: React.FC = () => {
  const auth = useContext(authContext);
  const isLoggedIn = auth?.isLoggedIn || !!auth?.walletAddress;

  if (!isLoggedIn) return <Landing />;
  else return <MainPage />;
};

export default HomePage;
