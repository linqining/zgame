import { useEffect, useState, useCallback } from 'react';
import Axios from 'axios';
import setAuthToken from '../helpers/setAuthToken';
import { useGlobalContext } from '../context/global/globalContext';
import { useCurrentAccount } from '@mysten/dapp-kit-react';
import { dAppKit, ZKLOGIN_CONFIG } from '../sui/config';
import {
  getZkLoginSessionManager,
  ZkLoginSession,
} from '../sui/zkLoginSession';
import { getSponsoredTransactionService } from '../sui/sponsoredTx';
import type { AuthMethod, ZkLoginState, SponsoredTxState } from '../types/sui';

interface UseAuthReturn {
  isLoggedIn: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (name: string, email: string, password: string) => Promise<void>;
  loadUser: (token: string) => Promise<void>;
  walletAddress: string | null;
  connectWallet: () => void;
  disconnectWallet: () => void;
  // zkLogin
  zkLoginState: ZkLoginState;
  loginWithZkLogin: (provider: string) => Promise<void>;
  handleZkLoginCallback: (jwt: string) => Promise<void>;
  // Sponsored transactions
  sponsoredTxState: SponsoredTxState;
  authMethod: AuthMethod | null;
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
  const [authMethod, setAuthMethod] = useState<AuthMethod | null>(
    (localStorage.getItem('authMethod') as AuthMethod) || null
  );

  // zkLogin state
  const [zkLoginState, setZkLoginState] = useState<ZkLoginState>({
    isInitialized: false,
    isLoggedIn: false,
    address: null,
    provider: null,
    isSessionValid: false,
  });

  // Sponsored tx state
  const [sponsoredTxState, setSponsoredTxState] = useState<SponsoredTxState>({
    isAvailable: false,
    lastTxDigest: null,
    isSubmitting: false,
    error: null,
  });

  const currentAccount = useCurrentAccount();

  useEffect(() => {
    setIsLoading(true);

    const storedToken = localStorage.getItem('token');
    if (storedToken) loadUser(storedToken);

    // Check existing zkLogin session
    checkZkLoginSession();

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
      if (prevWalletAddress && isLoggedIn && authMethod === 'wallet') {
        disconnectWallet();
      }
      setPrevWalletAddress(null);
      localStorage.removeItem('walletAddress');
    }
  }, [currentAccount]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-authenticate with backend when wallet connects
  useEffect(() => {
    if (walletAddress && !isLoggedIn && authRetryCount < 3 && authMethod === 'wallet') {
      const storedToken = localStorage.getItem('token');
      if (!storedToken) {
        authenticateWithWallet(walletAddress);
      } else {
        loadUser(storedToken);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [walletAddress, isLoggedIn, authRetryCount, authMethod]);

  // Check zkLogin session validity periodically
  useEffect(() => {
    if (!zkLoginState.isLoggedIn) return;

    const interval = setInterval(async () => {
      try {
        const manager = getZkLoginSessionManager();
        const isValid = await manager.isSessionValid();
        setZkLoginState(prev => ({ ...prev, isSessionValid: isValid }));
        if (!isValid) {
          // Session expired, need to re-login
          setZkLoginState(prev => ({
            ...prev,
            isLoggedIn: false,
            address: null,
            isSessionValid: false,
          }));
          setAuthMethod(null);
          localStorage.removeItem('authMethod');
        }
      } catch {
        // Ignore check errors
      }
    }, 60000); // Check every minute

    return () => clearInterval(interval);
  }, [zkLoginState.isLoggedIn]);

  const checkZkLoginSession = async () => {
    try {
      const manager = getZkLoginSessionManager();
      const session = manager.getSession();
      if (session) {
        const isValid = await manager.isSessionValid();
        setZkLoginState({
          isInitialized: true,
          isLoggedIn: isValid,
          address: isValid ? session.address : null,
          provider: localStorage.getItem('zklogin_provider'),
          isSessionValid: isValid,
        });
        if (isValid) {
          setAuthMethod((localStorage.getItem('authMethod') as AuthMethod) || null);
          setSponsoredTxState(prev => ({ ...prev, isAvailable: true }));
          // Auto-authenticate with backend if not already
          if (!isLoggedIn) {
            await authenticateWithZkLogin(session);
          }
        }
      } else {
        setZkLoginState(prev => ({ ...prev, isInitialized: true }));
      }
    } catch {
      setZkLoginState(prev => ({ ...prev, isInitialized: true }));
    }
  };

  // zkLogin: Initiate OAuth flow
  const loginWithZkLogin = async (provider: string): Promise<void> => {
    setIsLoading(true);
    try {
      const providerConfig = ZKLOGIN_CONFIG[provider as keyof typeof ZKLOGIN_CONFIG];
      if (!providerConfig?.clientId) {
        throw new Error(`OAuth client ID not configured for ${provider}. Set VITE_${provider.toUpperCase()}_CLIENT_ID in .env`);
      }

      const manager = getZkLoginSessionManager();
      const { url } = await manager.prepareOAuthUrl(
        provider,
        providerConfig.clientId,
        providerConfig.redirectUrl,
      );

      // Store provider for callback
      localStorage.setItem('zklogin_provider', provider);

      // Redirect to OAuth provider
      window.location.href = url;
    } catch (error) {
      console.error('zkLogin initiation failed:', error);
      setIsLoading(false);
    }
  };

  // zkLogin: Handle OAuth callback
  const handleZkLoginCallback = async (jwt: string): Promise<void> => {
    setIsLoading(true);
    try {
      const manager = getZkLoginSessionManager();
      const session = await manager.handleCallback(jwt);
      const provider = localStorage.getItem('zklogin_provider') || 'unknown';

      setZkLoginState({
        isInitialized: true,
        isLoggedIn: true,
        address: session.address,
        provider,
        isSessionValid: true,
      });

      const method = `zklogin_${provider}` as AuthMethod;
      setAuthMethod(method);
      localStorage.setItem('authMethod', method);

      // Authenticate with backend
      await authenticateWithZkLogin(session);

      setSponsoredTxState(prev => ({ ...prev, isAvailable: true }));
    } catch (error) {
      console.error('zkLogin callback failed:', error);
      setZkLoginState(prev => ({
        ...prev,
        isLoggedIn: false,
        address: null,
        isSessionValid: false,
      }));
    }
    setIsLoading(false);
  };

  // Authenticate zkLogin user with backend
  const authenticateWithZkLogin = async (session: ZkLoginSession): Promise<void> => {
    try {
      // Sign a message with the ephemeral key to prove ownership
      const message = `zgame-zklogin:${session.address}:${Date.now()}`;
      const messageBytes = new TextEncoder().encode(message);

      const { signature } = await session.ephemeralKeyPair.signPersonalMessage(messageBytes);

      const res = await Axios.post('/api/auth/zklogin', {
        address: session.address,
        signature,
        message,
        provider: session.decodedJwt.iss,
        email: session.decodedJwt.email,
      });

      const backendToken = res.data.token;
      if (backendToken) {
        localStorage.setItem('token', backendToken);
        setAuthToken(backendToken);
        await loadUser(backendToken);
        setAuthRetryCount(0);
      }
    } catch (error) {
      console.error('zkLogin backend auth failed:', error);
      setAuthRetryCount(prev => prev + 1);
    }
  };

  const authenticateWithWallet = async (address: string): Promise<void> => {
    setIsLoading(true);
    try {
      const message = `zgame-login:${address}:${Date.now()}`;
      const messageBytes = new TextEncoder().encode(message);

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
        setAuthMethod('wallet');
        localStorage.setItem('authMethod', 'wallet');
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
    localStorage.removeItem('authMethod');
    localStorage.removeItem('zklogin_provider');
    setIsLoggedIn(false);
    setId(null);
    setUserName(null);
    setEmail(null);
    setChipsAmount(null);
    setAuthMethod(null);

    // Clear zkLogin session
    try {
      const manager = getZkLoginSessionManager();
      manager.clearSession();
    } catch {
      // Manager not initialized yet
    }
    setZkLoginState({
      isInitialized: true,
      isLoggedIn: false,
      address: null,
      provider: null,
      isSessionValid: false,
    });
    setSponsoredTxState({
      isAvailable: false,
      lastTxDigest: null,
      isSubmitting: false,
      error: null,
    });
  }, [setId, setUserName, setEmail, setChipsAmount]);

  const connectWallet = useCallback((): void => {
    console.log('Use the ConnectButton component to connect wallet');
  }, []);

  const disconnectWallet = useCallback((): void => {
    const token = localStorage.getItem('token');
    if (token) {
      Axios.post('/api/auth/wallet/logout', {}, {
        headers: { 'x-auth-token': token },
      }).catch((err) => {
        console.error('wallet_logout backend call failed:', err);
      });
    }
    setWalletAddress(null);
    logout();
  }, [logout]);

  return {
    isLoggedIn,
    login,
    logout,
    register,
    loadUser,
    walletAddress: walletAddress || zkLoginState.address,
    connectWallet,
    disconnectWallet,
    zkLoginState,
    loginWithZkLogin,
    handleZkLoginCallback,
    sponsoredTxState,
    authMethod,
  };
};

export default useAuth;
