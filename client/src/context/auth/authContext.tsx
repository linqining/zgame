import React, { createContext } from 'react';
import type { ZkLoginState, SponsoredTxState, AuthMethod } from '../../types/sui';

export interface AuthContextType {
  isLoggedIn: boolean;
  // Legacy auth (keep for transition)
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (name: string, email: string, password: string) => Promise<void>;
  loadUser: (token: string) => Promise<void>;
  // Sui wallet auth
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

const authContext = createContext<AuthContextType | undefined>(undefined);

export default authContext;
