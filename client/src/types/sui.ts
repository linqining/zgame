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

// zkLogin 相关类型
export interface ZkLoginState {
  isInitialized: boolean;
  isLoggedIn: boolean;
  address: string | null;
  provider: string | null;       // 'google' | 'apple' | 'facebook' | 'twitch'
  isSessionValid: boolean;
}

// 赞助交易相关类型
export interface SponsoredTxState {
  isAvailable: boolean;          // 赞助服务是否可用
  lastTxDigest: string | null;
  isSubmitting: boolean;
  error: string | null;
}

// 游戏链上操作类型
export type GameAction = 'fold' | 'check' | 'call' | 'raise' | 'all_in';

export interface GameActionParams {
  action: GameAction;
  tableId: string;
  amount?: number;
  packageId?: string;
}

// 认证方式
export type AuthMethod = 'wallet' | 'zklogin_google' | 'zklogin_apple' | 'zklogin_facebook' | 'zklogin_twitch';
