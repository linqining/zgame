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
  // Shinami Gas Station proxy endpoint. The backend forwards gasless
  // transactions to Shinami using SHINAMI_API_KEY.
  apiUrl: import.meta.env.VITE_SPONSOR_API_URL || '/api/sponsor/transaction',
  saltServiceUrl: import.meta.env.VITE_SALT_SERVICE_URL || '/api/auth/zklogin/salt',
  // zkLogin prover proxy. Shinami's prover does not support CORS, so the
  // frontend calls this backend endpoint which forwards to Shinami with the
  // X-API-Key header. Set VITE_ZKLOGIN_PROVER_URL to override.
  proverServiceUrl: import.meta.env.VITE_ZKLOGIN_PROVER_URL || '/api/auth/zklogin/prover',
};

// Move package ID for game contracts (upgraded/latest, used for function calls)
export const PACKAGE_ID = import.meta.env.VITE_PACKAGE_ID || '';

// Original package ID where struct types were first published (used for type queries).
// After an upgrade, object types and event types are still anchored to this ID.
// If not set, falls back to PACKAGE_ID (compatible with first publish).
export const ORIGIN_PACKAGE_ID = import.meta.env.VITE_ORIGIN_PACKAGE_ID || PACKAGE_ID;

// Eagerly create a client for the default network and initialize the zkLogin
// session manager + sponsored tx service at module load. These services must
// be available before any wallet connects — e.g. on the OAuth callback page
// (/auth/callback) the user arrives from an OAuth redirect with no wallet
// connected, so dApp Kit's lazy `createClient` callback below has not run yet.
const defaultNetwork = networks[0]; // testnet — 与后端一致，避免 zkLogin prover 网络不匹配
export const defaultClient = new SuiGrpcClient({
  network: defaultNetwork,
  baseUrl: networkUrls[defaultNetwork] || networkUrls.testnet,
});
initZkLoginSessionManager(defaultClient, defaultNetwork, SPONSOR_CONFIG.saltServiceUrl, SPONSOR_CONFIG.proverServiceUrl);
initSponsoredTransactionService(defaultClient, SPONSOR_CONFIG.apiUrl);

export const dAppKit = createDAppKit({
  networks: [...networks],
  createClient: (network) =>
    new SuiGrpcClient({ network, baseUrl: networkUrls[network] || networkUrls.testnet }),
  defaultNetwork,
});
