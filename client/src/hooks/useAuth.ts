import { useEffect, useState, useCallback } from 'react';
import httpClient from '../helpers/httpClient';
import setAuthToken from '../helpers/setAuthToken';
import { getToken } from '../helpers/getToken';
import { useGlobalContext } from '../context/global/globalContext';
import { useCurrentAccount } from '@mysten/dapp-kit-react';
import { dAppKit, ZKLOGIN_CONFIG } from '../sui/config';
import {
  getZkLoginSessionManager,
  ZkLoginSession,
} from '../sui/zkLoginSession';
import { getSponsoredTransactionService } from '../sui/sponsoredTx';
import type { AuthMethod, ZkLoginState, SponsoredTxState } from '../types/sui';
import { logger } from '../helpers/logger';

interface UseAuthReturn {
  isLoggedIn: boolean;
  logout: () => void;
  loadUser: (token: string) => Promise<void>;
  walletAddress: string | null;
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
  const token = getToken();
  if (token) setAuthToken(token);

  const {
    setId,
    setIsLoading,
    setUserName,
    setEmail,
    setChipsAmount,
    setSuiBalance,
  } = useGlobalContext();

  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [walletAddress, setWalletAddress] = useState<string | null>(
    localStorage.getItem('walletAddress')
  );
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
    let cancelled = false;
    const init = async () => {
      setIsLoading(true);

      // If there's no stored token, clear stale auth state. We intentionally
      // do NOT call dAppKit.disconnectWallet() here — doing so races with
      // manual wallet connection. The wallet auto-authenticate effect below
      // only fires when currentAccount is set and there is no stored token,
      // which is the expected behavior for both auto-reconnect and manual
      // connect.
      const storedToken = getToken();
      if (!storedToken) {
        localStorage.removeItem('walletAddress');
        localStorage.removeItem('authMethod');
        localStorage.removeItem('zklogin_provider');
        setWalletAddress(null);
        setAuthMethod(null);
      }

      if (storedToken) await loadUser(storedToken);

      // Check existing zkLogin session
      await checkZkLoginSession();

      if (!cancelled) setIsLoading(false);
    };
    init();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync wallet address from dApp Kit
  useEffect(() => {
    if (currentAccount) {
      setWalletAddress(currentAccount.address);
      localStorage.setItem('walletAddress', currentAccount.address);
    } else {
      setWalletAddress(null);
      localStorage.removeItem('walletAddress');
    }
  }, [currentAccount]);

  // 钱包连接后自动向后端认证。zkLogin 回调在 /auth/callback 路由独立完成，
  // 不经过此 effect，因此不会互相干扰。
  useEffect(() => {
    if (currentAccount && !isLoggedIn) {
      const storedToken = getToken();
      if (!storedToken) {
        authenticateWithWallet(currentAccount.address);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentAccount, isLoggedIn]);

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
        if (isValid) {
          setZkLoginState({
            isInitialized: true,
            isLoggedIn: true,
            address: session.address,
            provider: localStorage.getItem('zklogin_provider'),
            isSessionValid: true,
          });
          setAuthMethod((localStorage.getItem('authMethod') as AuthMethod) || null);
          setSponsoredTxState(prev => ({ ...prev, isAvailable: true }));
          // Auto-authenticate with backend if not already
          if (!isLoggedIn) {
            await authenticateWithZkLogin(session);
          }
        } else {
          // Session expired — clear stale zkLogin state. We intentionally
          // do NOT call dAppKit.disconnectWallet() here: dAppKit does not
          // distinguish between native wallet accounts and zkLogin accounts,
          // so disconnecting would also kill a native wallet the user is
          // actively trying to log in with. The zkLogin session itself is
          // cleared via manager.clearSession(), which is sufficient.
          logger.warn('[Auth] zkLogin session expired, clearing session');
          manager.clearSession();
          setAuthMethod(null);
          localStorage.removeItem('authMethod');
          localStorage.removeItem('zklogin_provider');
          setZkLoginState({
            isInitialized: true,
            isLoggedIn: false,
            address: null,
            provider: null,
            isSessionValid: false,
          });
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
    logger.log('[Auth] loginWithZkLogin called, provider:', provider);
    setIsLoading(true);
    try {
      const providerConfig = ZKLOGIN_CONFIG[provider as keyof typeof ZKLOGIN_CONFIG];
      if (!providerConfig?.clientId) {
        throw new Error(`OAuth client ID not configured for ${provider}. Set VITE_${provider.toUpperCase()}_CLIENT_ID in .env`);
      }

      // Clear ALL stale auth state before redirecting to OAuth. The callback
      // page (ZkLoginCallback) only calls handleZkLoginCallback when
      // isLoggedIn is false. If a stale token remains, loadUser() succeeds
      // on the callback page, sets isLoggedIn=true, and the zkLogin flow is
      // skipped entirely — /auth/zklogin/salt and /auth/zklogin never fire.
      localStorage.removeItem('token');
      localStorage.removeItem('walletAddress');
      setAuthToken(null);
      setIsLoggedIn(false);
      setWalletAddress(null);
      setAuthMethod(null);

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
      logger.error('zkLogin initiation failed:', error);
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
      logger.error('zkLogin callback failed:', error);
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
      // Sign a message with zkLogin signature to prove ownership.
      // Must use zkLogin signature format (not plain Ed25519) so the backend
      // can verify it as a UserSignature::ZkLogin and derive the correct address.
      const message = `zgame-zklogin:${session.address}:${Date.now()}`;
      const messageBytes = new TextEncoder().encode(message);

      const manager = getZkLoginSessionManager();
      const signature = await manager.signPersonalMessage(messageBytes);

      const res = await httpClient.post('/auth/zklogin', {
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
      }
    } catch (error) {
      logger.error('zkLogin backend auth failed:', error);
    }
  };

  const authenticateWithWallet = async (address: string): Promise<void> => {
    setIsLoading(true);
    try {
      const message = `zgame-login:${address}:${Date.now()}`;
      const messageBytes = new TextEncoder().encode(message);
      const signResult = await dAppKit.signPersonalMessage({ message: messageBytes });

      const res = await httpClient.post('/auth/wallet', {
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
      }
    } catch (error) {
      logger.error('[Auth] Wallet authentication failed:', error);
    }
    setIsLoading(false);
  };

  const loadUser = async (token: string): Promise<void> => {
    try {
      const res = await httpClient.get('/auth');

      const { _id, name, address, chipsAmount, suiBalance } = res.data;

      setIsLoggedIn(true);
      setId(_id);
      setUserName(name);
      if (address) {
        setWalletAddress(address);
        localStorage.setItem('walletAddress', address);
      }
      setChipsAmount(chipsAmount ?? 0);
      setSuiBalance(suiBalance ?? 0);
    } catch (error) {
      localStorage.removeItem('token');
      logger.error('loadUser failed:', error);
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
    setSuiBalance(null);
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
  }, [setId, setUserName, setEmail, setChipsAmount, setSuiBalance]);

  const disconnectWallet = useCallback((): void => {
    const token = getToken();
    if (token) {
      httpClient.post('/auth/wallet/logout', {}).catch((err) => {
        logger.error('wallet_logout backend call failed:', err);
      });
    }
    setWalletAddress(null);
    logout();
  }, [logout]);

  return {
    isLoggedIn,
    logout,
    loadUser,
    walletAddress,
    disconnectWallet,
    zkLoginState,
    loginWithZkLogin,
    handleZkLoginCallback,
    sponsoredTxState,
    authMethod,
  };
};

export default useAuth;
