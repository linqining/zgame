import React, { createContext } from 'react';

export interface AuthContextType {
  isLoggedIn: boolean;
  // Legacy auth (keep for transition)
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (name: string, email: string, password: string) => Promise<void>;
  loadUser: (token: string) => Promise<void>;
  // Sui wallet auth (new)
  walletAddress: string | null;
  connectWallet: () => void;
  disconnectWallet: () => void;
}

const authContext = createContext<AuthContextType | undefined>(undefined);

export default authContext;
