import React, { createContext } from 'react';
import type { ZkLoginState, SponsoredTxState, AuthMethod } from '../../types/sui';

export interface AuthContextType {
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

const authContext = createContext<AuthContextType | undefined>(undefined);

export default authContext;
