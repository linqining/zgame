// Sui 钱包和交易相关类型

export interface SuiConfig {
  networks: {
    testnet: { url: string };
    mainnet: { url: string };
  };
  defaultNetwork: 'testnet' | 'mainnet';
}

export interface BetTransactionParams {
  packageId: string;
  tableId: string;
  amount: number;
}

export interface WalletConnectionState {
  isConnected: boolean;
  isConnecting: boolean;
  address: string | null;
  error: string | null;
}
