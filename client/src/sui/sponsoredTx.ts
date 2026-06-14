import { Transaction } from '@mysten/sui/transactions';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { getZkLoginSessionManager } from './zkLoginSession';

// Base64 helpers (replacing removed fromB64/toB64 from @mysten/sui/utils)
function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Sponsored transaction flow (two-endpoint approach):
// 1. Frontend calls GET /api/sponsor/gas-info to get sponsor's gas coin details
// 2. Frontend builds complete TransactionData with gas info (gasPayment, gasOwner, gasBudget, gasPrice)
// 3. Frontend calls POST /api/sponsor/transaction with tx_bytes to get sponsor's signature
// 4. Frontend signs with zkLogin ephemeral key (no wallet popup)
// 5. Frontend submits dual-signed transaction

export interface GasInfoResponse {
  sponsor_address: string;
  gas_coin_id: string;
  gas_coin_version: string;
  gas_coin_digest: string;
  gas_price: string;
  gas_budget: number;
}

export interface SponsorTransactionRequest {
  tx_bytes: string;  // base64 encoded complete TransactionData bytes
}

export interface SponsorTransactionResponse {
  gas_signature: string;  // sponsor's signature
}

export interface SponsoredTransactionResult {
  digest: string;
  success: boolean;
  error?: string;
}

export class SponsoredTransactionService {
  private client: SuiGrpcClient;
  private sponsorApiBaseUrl: string;

  constructor(client: SuiGrpcClient, sponsorApiUrl?: string) {
    this.client = client;
    // Extract base URL (strip /transaction suffix if present from old config)
    const url = sponsorApiUrl || '/api/sponsor/transaction';
    this.sponsorApiBaseUrl = url.replace(/\/transaction$/, '');
  }

  // Build a game action transaction and execute it with sponsorship
  async executeSponsoredGameAction(transaction: Transaction): Promise<SponsoredTransactionResult> {
    const zkLoginManager = getZkLoginSessionManager();
    const session = zkLoginManager.getSession();

    if (!session) {
      return { digest: '', success: false, error: 'No zkLogin session. Please login first.' };
    }

    try {
      // Step 1: Fetch gas info from sponsor backend
      const gasInfo = await this.fetchGasInfo();
      if (!gasInfo) {
        return { digest: '', success: false, error: 'Failed to fetch gas info from sponsor' };
      }

      // Step 2: Build complete transaction with gas info
      transaction.setSender(session.address);
      transaction.setGasOwner(gasInfo.sponsor_address);
      transaction.setGasBudget(gasInfo.gas_budget);
      transaction.setGasPrice(BigInt(gasInfo.gas_price));
      transaction.setGasPayment([{
        objectId: gasInfo.gas_coin_id,
        version: gasInfo.gas_coin_version,
        digest: gasInfo.gas_coin_digest,
      }]);

      const txBytes = await transaction.build({ client: this.client });
      const txBytesB64 = toB64(txBytes);

      // Step 3: Request sponsor's signature
      const sponsorResponse = await this.requestSponsorSignature({ tx_bytes: txBytesB64 });

      if (!sponsorResponse.gas_signature) {
        return { digest: '', success: false, error: 'Sponsor signature request failed' };
      }

      // Step 4: Sign with zkLogin ephemeral key (local, no wallet popup)
      const { signature: userSignature } = await session.ephemeralKeyPair.signTransaction(txBytes);

      // Compose zkLogin signature
      const { getZkLoginSignature, genAddressSeed } = await import('@mysten/sui/zklogin');
      const addressSeed = genAddressSeed(
        session.userSalt,
        'sub',
        session.decodedJwt.sub,
        session.decodedJwt.aud,
      );

      const zkLoginSignature = getZkLoginSignature({
        inputs: {
          ...session.zkProof,
          addressSeed: addressSeed.toString(),
        },
        maxEpoch: session.maxEpoch,
        userSignature,
      });

      // Step 5: Submit dual-signed transaction
      const result = await this.client.executeTransaction({
        transaction: txBytes,
        signatures: [zkLoginSignature, sponsorResponse.gas_signature],
        include: {
          effects: true,
        },
      });

      if (result.$kind === 'FailedTransaction') {
        const failedTx = result.FailedTransaction!;
        return {
          digest: failedTx.digest ?? '',
          success: false,
          error: failedTx.effects?.status?.error?.message || 'Transaction failed',
        };
      }

      const tx = result.Transaction!;
      const success = tx.effects?.status?.success === true;
      return {
        digest: tx.digest ?? '',
        success,
        error: success ? undefined : (tx.effects?.status?.error?.message || 'Unknown error'),
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      console.error('[SponsoredTx] Failed:', msg);
      return { digest: '', success: false, error: msg };
    }
  }

  // Execute a transaction without sponsorship (player pays gas)
  // Used as fallback when sponsor service is unavailable
  async executeGameAction(transaction: Transaction): Promise<SponsoredTransactionResult> {
    const zkLoginManager = getZkLoginSessionManager();

    try {
      const digest = await zkLoginManager.executeTransaction(transaction);
      return { digest, success: true };
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return { digest: '', success: false, error: msg };
    }
  }

  // Fetch gas info from sponsor backend (GET /api/sponsor/gas-info)
  private async fetchGasInfo(): Promise<GasInfoResponse | null> {
    try {
      const url = `${this.sponsorApiBaseUrl}/gas-info`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'x-auth-token': localStorage.getItem('token') || '',
        },
      });

      if (!response.ok) {
        console.error('[SponsoredTx] Gas info request failed:', response.status);
        return null;
      }

      return await response.json();
    } catch (error) {
      console.error('[SponsoredTx] Gas info fetch error:', error);
      return null;
    }
  }

  // Request sponsor's signature (POST /api/sponsor/transaction)
  private async requestSponsorSignature(request: SponsorTransactionRequest): Promise<SponsorTransactionResponse> {
    const url = `${this.sponsorApiBaseUrl}/transaction`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-auth-token': localStorage.getItem('token') || '',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Sponsor signature request failed' }));
      throw new Error(error.error || `Sponsor service error: ${response.status}`);
    }

    return response.json();
  }
}

// Singleton instance
let _instance: SponsoredTransactionService | null = null;

export function getSponsoredTransactionService(client?: SuiGrpcClient): SponsoredTransactionService {
  if (!_instance && client) {
    _instance = new SponsoredTransactionService(client);
  }
  if (!_instance) {
    throw new Error('SponsoredTransactionService not initialized. Call with client first.');
  }
  return _instance;
}

export function initSponsoredTransactionService(
  client: SuiGrpcClient,
  sponsorApiUrl?: string,
): SponsoredTransactionService {
  _instance = new SponsoredTransactionService(client, sponsorApiUrl);
  return _instance;
}

// Helper: Build a game action transaction
export function buildGameActionTransaction(
  packageId: string,
  action: string,
  module: string,
  args: { objectId?: string; pureU64?: number; pureAddress?: string }[],
): Transaction {
  const tx = new Transaction();

  const arguments_ = args.map((arg) => {
    if (arg.objectId) return tx.object(arg.objectId);
    if (arg.pureU64 !== undefined) return tx.pure.u64(arg.pureU64);
    if (arg.pureAddress) return tx.pure.address(arg.pureAddress);
    throw new Error('Invalid argument type');
  });

  tx.moveCall({
    target: `${packageId}::${module}::${action}`,
    arguments: arguments_,
  });

  return tx;
}
