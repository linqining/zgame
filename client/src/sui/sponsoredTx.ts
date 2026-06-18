import { Transaction } from '@mysten/sui/transactions';
import { TransactionDataBuilder } from '@mysten/sui/transactions';
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

function fromB64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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

// ---------------------------------------------------------------------------
// /api/sui/action/build 请求/响应类型
// ---------------------------------------------------------------------------

/** POST /api/sui/action/build 请求体 */
export interface BuildActionRequest {
  /** 动作类型: fold | check | call | raise | join_and_shuffle */
  action: string;
  /** 链上 Table 对象 ID (hex) */
  table_id: string;
  /** 座位索引 */
  seat_index: number;
  /** raise 动作需要的总下注额 */
  total_bet?: number;
  /** join_and_shuffle 需要的买入金额 */
  buy_in?: number;
  /** join_and_shuffle 需要的玩家公钥 (hex 或 base64, 48 bytes) */
  pk?: string;
  /** join_and_shuffle 需要的 pk 所有权证明 (hex 或 base64, 80 bytes) */
  pk_ownership_proof?: string;
  /** join_and_shuffle 需要的输出牌组 (hex 或 base64, flat 96*N bytes) */
  output_cards?: string;
  /** join_and_shuffle 需要的 remask 证明 (hex 或 base64) */
  remask_proof_bytes?: string;
  /** join_and_shuffle 需要的 shuffle 证明 (hex 或 base64) */
  shuffle_proof_bytes?: string;
}

/** POST /api/sui/action/build 响应体 */
export interface BuildActionResponse {
  /** base64 编码的 BCS 序列化 TransactionKind 字节 */
  tx_kind: string;
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

  // ---------------------------------------------------------------------------
  // 新流程：通过后端 /api/sui/action/build 构建 TransactionKind，再组装完整交易
  //
  // 流程：
  // 1. POST /api/sui/action/build → 获取 tx_kind (base64 TransactionKind BCS)
  // 2. GET /api/sponsor/gas-info → 获取 sponsor gas 信息
  // 3. TransactionDataBuilder.fromKindBytes(tx_kind) → 反序列化
  // 4. 设置 sender + gasData → build() 生成完整 tx_bytes
  // 5. zkLogin 签名 tx_bytes
  // 6. POST /api/sponsor/transaction → 获取 sponsor 签名
  // 7. 提交双签名交易到 Sui
  // ---------------------------------------------------------------------------

  /**
   * 调用后端 /api/sui/action/build 构建 TransactionKind。
   * 返回 base64 编码的 tx_kind。
   */
  async buildActionTxKind(request: BuildActionRequest): Promise<string> {
    const response = await fetch('/api/sui/action/build', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-auth-token': localStorage.getItem('token') || '',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Build action request failed' }));
      throw new Error(error.error || `Build action failed: ${response.status}`);
    }

    const data: BuildActionResponse = await response.json();
    if (!data.tx_kind) {
      throw new Error('Missing tx_kind in build action response');
    }
    return data.tx_kind;
  }

  /**
   * 执行赞助的游戏操作（通过后端构建 PTB）。
   *
   * @param request 游戏操作参数（action, table_id, seat_index, 以及 join_and_shuffle 需要的加密参数）
   * @returns 交易结果
   */
  async executeSponsoredAction(request: BuildActionRequest): Promise<SponsoredTransactionResult> {
    const zkLoginManager = getZkLoginSessionManager();
    const session = zkLoginManager.getSession();

    if (!session) {
      return { digest: '', success: false, error: 'No zkLogin session. Please login first.' };
    }

    try {
      // Step 1: 构建 TransactionKind
      const txKindB64 = await this.buildActionTxKind(request);
      const txKindBytes = fromB64(txKindB64);

      // Step 2: 获取 gas 信息
      const gasInfo = await this.fetchGasInfo();
      if (!gasInfo) {
        return { digest: '', success: false, error: 'Failed to fetch gas info from sponsor' };
      }

      // Step 3: 从 TransactionKind 反序列化为 TransactionDataBuilder
      const builder = TransactionDataBuilder.fromKindBytes(txKindBytes);

      // Step 4: 设置 sender 和 gasData
      const gasData = {
        budget: gasInfo.gas_budget,
        price: gasInfo.gas_price,
        owner: gasInfo.sponsor_address,
        payment: [{
          objectId: gasInfo.gas_coin_id,
          version: gasInfo.gas_coin_version,
          digest: gasInfo.gas_coin_digest,
        }],
      };

      // Step 5: 构建完整 tx_bytes
      const txBytes = builder.build({
        overrides: {
          sender: session.address,
          gasData,
        },
      });
      const txBytesB64 = toB64(txBytes);

      // Step 6: zkLogin 签名
      const { signature: userSignature } = await session.ephemeralKeyPair.signTransaction(txBytes);

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

      // Step 7: 获取 sponsor 签名
      const sponsorResponse = await this.requestSponsorSignature({ tx_bytes: txBytesB64 });
      if (!sponsorResponse.gas_signature) {
        return { digest: '', success: false, error: 'Sponsor signature request failed' };
      }

      // Step 8: 提交双签名交易
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
      console.error('[SponsoredAction] Failed:', msg);
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
