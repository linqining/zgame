import { useEffect, useState, useCallback } from 'react';
import Axios from 'axios';
import setAuthToken from '../helpers/setAuthToken';
import { useGlobalContext } from '../context/global/globalContext';
import { useCurrentAccount } from '@mysten/dapp-kit-react';
import { dAppKit } from '../sui/config';

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
  const [walletAddress, setWalletAddress] = useState<string | null>(
    localStorage.getItem('walletAddress')
  );
  const [prevWalletAddress, setPrevWalletAddress] = useState<string | null>(null);
  const [authRetryCount, setAuthRetryCount] = useState(0);

  const currentAccount = useCurrentAccount();

  useEffect(() => {
    setIsLoading(true);

    const storedToken = localStorage.getItem('token');
    if (storedToken) loadUser(storedToken);

    setIsLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync wallet address from dApp Kit and handle disconnect
  useEffect(() => {
    if (currentAccount) {
      setWalletAddress(currentAccount.address);
      setPrevWalletAddress(currentAccount.address);
      localStorage.setItem('walletAddress', currentAccount.address);
    } else {
      setWalletAddress(null);
      // Wallet was connected before but now disconnected
      if (prevWalletAddress && isLoggedIn) {
        disconnectWallet();
      }
      setPrevWalletAddress(null);
      localStorage.removeItem('walletAddress');
    }
  }, [currentAccount]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-authenticate with backend when wallet connects (skip if already logged in)
  useEffect(() => {
    if (walletAddress && !isLoggedIn && authRetryCount < 3) {
      const storedToken = localStorage.getItem('token');
      if (!storedToken) {
        authenticateWithWallet(walletAddress);
      } else {
        loadUser(storedToken);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [walletAddress, isLoggedIn, authRetryCount]);

  const authenticateWithWallet = async (address: string): Promise<void> => {
    setIsLoading(true);
    try {
      // Construct a message for the user to sign
      const message = `zgame-login:${address}:${Date.now()}`;
      const messageBytes = new TextEncoder().encode(message);

      // Request signature from the wallet
      const signResult = await dAppKit.signPersonalMessage({
        message: messageBytes,
      });

      const res = await Axios.post('/api/auth/wallet', {
        address,
        signature: signResult.signature,
        message,
      });

      const token = res.data.token;

      if (token) {
        localStorage.setItem('token', token);
        setAuthToken(token);
        await loadUser(token);
        setAuthRetryCount(0);
      }
    } catch (error) {
      const err = error as Error;
      console.error('Wallet authentication failed:', error);
      if (err.message?.includes('Incorrect password') || err.message?.includes('User rejected')) {
        console.warn('[Auth] Wallet signing rejected or failed, will not auto-retry');
      }
      setAuthRetryCount(prev => prev + 1);
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
      setAuthRetryCount(prev => prev + 1);
      console.error('loadUser failed:', error);
    }
  };

  const logout = useCallback((): void => {
    localStorage.removeItem('token');
    localStorage.removeItem('walletAddress');
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
    // Call backend wallet_logout endpoint
    const token = localStorage.getItem('token');
    if (token) {
      Axios.post('/api/auth/wallet/logout', {}, {
        headers: { 'x-auth-token': token },
      }).catch((err) => {
        console.error('wallet_logout backend call failed:', err);
      });
    }
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
