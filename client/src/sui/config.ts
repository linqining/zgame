import { createDAppKit } from '@mysten/dapp-kit-react';
import { SuiGrpcClient } from '@mysten/sui/grpc';

const networks = ['testnet', 'mainnet'] as const;

const networkUrls: Record<string, string> = {
  testnet: 'https://fullnode.testnet.sui.io:443',
  mainnet: 'https://fullnode.mainnet.sui.io:443',
};

export const dAppKit = createDAppKit({
  networks: [...networks],
  createClient: (network) => new SuiGrpcClient({ network, baseUrl: networkUrls[network] || networkUrls.testnet }),
  defaultNetwork: networks[0],
});
