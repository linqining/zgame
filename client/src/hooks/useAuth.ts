import { useEffect, useState, useCallback } from 'react';
import Axios from 'axios';
import setAuthToken from '../helpers/setAuthToken';
import { useGlobalContext } from '../context/global/globalContext';
import { useCurrentAccount } from '@mysten/dapp-kit-react';

interface UseAuthReturn {
  isLoggedIn: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (name: string, email: string, password: string) => Promise<void>;
  loadUser: (token: string) => Promise<void>;
  walletAddress: string | null;
  connectWallet: () => void;
  disconnectWallet: () => void;
}

const useAuth = (): UseAuthReturn => {
  const token = localStorage.getItem('token');
  if (token) setAuthToken(token);

  const {
    setId,
    setIsLoading,
    setUserName,
    setEmail,
    setChipsAmount,
  } = useGlobalContext();

  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [walletAddress, setWalletAddress] = useState<string | null>(null);

  const currentAccount = useCurrentAccount();

  useEffect(() => {
    setIsLoading(true);

    const storedToken = localStorage.getItem('token');
    if (storedToken) loadUser(storedToken);

    setIsLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync wallet address from dApp Kit
  useEffect(() => {
    if (currentAccount) {
      setWalletAddress(currentAccount.address);
    } else {
      setWalletAddress(null);
    }
  }, [currentAccount]);

  // Auto-authenticate with backend when wallet connects
  useEffect(() => {
    if (walletAddress && !isLoggedIn) {
      authenticateWithWallet(walletAddress);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [walletAddress]);

  const authenticateWithWallet = async (address: string): Promise<void> => {
    setIsLoading(true);
    try {
      const res = await Axios.post('/api/auth/wallet', {
        walletAddress: address,
      });

      const token = res.data.token;

      if (token) {
        localStorage.setItem('token', token);
        setAuthToken(token);
        await loadUser(token);
      }
    } catch (error) {
      console.error('Wallet authentication failed:', error);
    }
    setIsLoading(false);
  };

  const register = async (name: string, email: string, password: string): Promise<void> => {
    setIsLoading(true);
    try {
      const res = await Axios.post('/api/users', {
        name,
        email,
        password,
      });

      const token = res.data.token;

      if (token) {
        localStorage.setItem('token', token);
        setAuthToken(token);
        await loadUser(token);
      }
    } catch (error) {
      alert(error);
    }
    setIsLoading(false);
  };

  const login = async (emailAddress: string, password: string): Promise<void> => {
    setIsLoading(true);
    try {
      const res = await Axios.post('/api/auth', {
        email: emailAddress,
        password,
      });

      const token = res.data.token;

      if (token) {
        localStorage.setItem('token', token);
        setAuthToken(token);
        await loadUser(token);
      }
    } catch (error) {
      alert(error);
    }
    setIsLoading(false);
  };

  const loadUser = async (token: string): Promise<void> => {
    try {
      const res = await Axios.get('/api/auth', {
        headers: {
          'x-auth-token': token,
        },
      });

      const { _id, name, email, chipsAmount } = res.data;

      setIsLoggedIn(true);
      setId(_id);
      setUserName(name);
      setEmail(email);
      setChipsAmount(chipsAmount);
    } catch (error) {
      localStorage.removeItem('token');
      alert(error);
    }
  };

  const logout = useCallback((): void => {
    localStorage.removeItem('token');
    setIsLoggedIn(false);
    setId(null);
    setUserName(null);
    setEmail(null);
    setChipsAmount(null);
  }, [setId, setUserName, setEmail, setChipsAmount]);

  const connectWallet = useCallback((): void => {
    // Wallet connection is handled by the ConnectButton component from dapp-kit
    // This is a placeholder for programmatic connection if needed
    console.log('Use the ConnectButton component to connect wallet');
  }, []);

  const disconnectWallet = useCallback((): void => {
    // Wallet disconnection is handled internally by dapp-kit
    setWalletAddress(null);
    logout();
  }, [logout]);

  return {
    isLoggedIn,
    login,
    logout,
    register,
    loadUser,
    walletAddress,
    connectWallet,
    disconnectWallet,
  };
};

export default useAuth;
