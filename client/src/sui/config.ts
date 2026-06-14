import { createDAppKit } from '@mysten/dapp-kit-react';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { initZkLoginSessionManager } from './zkLoginSession';
import { initSponsoredTransactionService } from './sponsoredTx';

const networks = ['testnet', 'mainnet'] as const;
export type NetworkName = typeof networks[number];

const networkUrls: Record<string, string> = {
  testnet: 'https://fullnode.testnet.sui.io:443',
  mainnet: 'https://fullnode.mainnet.sui.io:443',
};

// zkLogin OAuth configuration
export const ZKLOGIN_CONFIG = {
  google: {
    clientId: import.meta.env.VITE_GOOGLE_CLIENT_ID || '',
    redirectUrl: import.meta.env.VITE_ZKLOGIN_REDIRECT_URL || `${window.location.origin}/auth/callback`,
  },
  apple: {
    clientId: import.meta.env.VITE_APPLE_CLIENT_ID || '',
    redirectUrl: import.meta.env.VITE_ZKLOGIN_REDIRECT_URL || `${window.location.origin}/auth/callback`,
  },
  facebook: {
    clientId: import.meta.env.VITE_FACEBOOK_CLIENT_ID || '',
    redirectUrl: import.meta.env.VITE_ZKLOGIN_REDIRECT_URL || `${window.location.origin}/auth/callback`,
  },
  twitch: {
    clientId: import.meta.env.VITE_TWITCH_CLIENT_ID || '',
    redirectUrl: import.meta.env.VITE_ZKLOGIN_REDIRECT_URL || `${window.location.origin}/auth/callback`,
  },
};

// Sponsored transaction configuration
export const SPONSOR_CONFIG = {
  apiUrl: import.meta.env.VITE_SPONSOR_API_URL || '/api/sponsor/transaction',
  saltServiceUrl: import.meta.env.VITE_SALT_SERVICE_URL || '/api/auth/zklogin/salt',
};

// Move package ID for game contracts
export const PACKAGE_ID = import.meta.env.VITE_PACKAGE_ID || '';

export const dAppKit = createDAppKit({
  networks: [...networks],
  createClient: (network) => {
    const client = new SuiGrpcClient({ network, baseUrl: networkUrls[network] || networkUrls.testnet });
    // Initialize zkLogin session manager and sponsored tx service with this client
    initZkLoginSessionManager(client, network, SPONSOR_CONFIG.saltServiceUrl);
    initSponsoredTransactionService(client, SPONSOR_CONFIG.apiUrl);
    return client;
  },
  defaultNetwork: networks[0],
});
