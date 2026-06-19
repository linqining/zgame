import { Transaction } from '@mysten/sui/transactions';
import { SuiGrpcClient } from '@mysten/sui/grpc';
import { getZkLoginSessionManager } from './zkLoginSession';
import { fromB64, toB64 } from './utils';
import httpClient from '../helpers/httpClient';

// Sponsored transaction flow (Shinami Gas Station):
// 1. Frontend builds a gasless transaction (TransactionKind + sender, no gas info)
//    using Transaction.build({ onlyTransactionKind: true })
// 2. Frontend POSTs the gasless tx to /api/sponsor/transaction (backend proxy)
// 3. Backend forwards to Shinami Gas Station, returns sponsored txBytes + gas signature
// 4. Frontend signs the sponsored txBytes with zkLogin ephemeral key
// 5. Frontend submits both signatures (zkLogin + gas) to the Sui network
//
// On stale gas coin errors ("Could not find the referenced object"), the
// transaction is automatically re-sponsored and resubmitted.

export interface SponsorTransactionRequest {
  /** Base64-encoded TransactionKind bytes (no gas info) */
  tx_kind: string;
  /** Sender address (hex, e.g. 0x...) */
  sender: string;
  /** Optional gas budget. If omitted, Shinami estimates it. */
  gas_budget?: number;
}

export interface SponsorTransactionResponse {
  /** Base64-encoded complete TransactionData bytes (with gas info from Shinami) */
  tx_bytes: string;
  /** Gas owner's (Shinami's) signature */
  signature: string;
  /** Transaction digest */
  tx_digest: string;
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
  /** 动作类型: fold | check | call | raise | join_and_shuffle_verified */
  action: string;
  /** 链上 Table 对象 Id (hex) */
  table_id: string;
  /** 座位索引 */
  seat_index: number;
  /** raise 动作需要的总下注额 */
  total_bet?: number;
  /** join_and_shuffle_verified 需要的买入 SUI Coin 对象 Id (hex)，合约已改为接收 Coin<SUI> */
  coin_object_id?: string;
  /** join_and_shuffle_verified 需要的玩家公钥 (hex 或 base64, 48 bytes) */
  pk?: string;
  /** join_and_shuffle_verified 需要的 pk 所有权证明 (hex 或 base64, 80 bytes) */
  pk_ownership_proof?: string;
  /** join_and_shuffle_verified 需要的输出牌组 (hex 或 base64, flat 96*N bytes) */
  output_cards?: string;
  /** join_and_shuffle_verified 需要的 remask 证明 (hex 或 base64) */
  remask_proof_bytes?: string;
  /** join_and_shuffle_verified 需要的 shuffle 证明 (hex 或 base64) */
  shuffle_proof_bytes?: string;
  /** leave_with_proof_verified 需要的 leave 证明 (hex 或 base64) */
  leave_proof_bytes?: string;
}

/** POST /api/sui/action/build 响应体 */
export interface BuildActionResponse {
  /** base64 编码的 BCS 序列化 TransactionKind 字节 */
  tx_kind: string;
}

/** Maximum retry attempts for stale gas coin errors */
const MAX_GAS_RETRY_ATTEMPTS = 3;

/** Decode a potentially URL-encoded error message */
function decodeMsg(msg: string): string {
  try { return decodeURIComponent(msg); } catch { return msg; }
}

/** Check if an error message indicates a retryable stale gas coin / timeout */
function isRetryableError(msg: string): boolean {
  const decoded = decodeMsg(msg);
  return decoded.includes('Could not find the referenced object')
    || decoded.includes('timed out before finality')
    || decoded.includes('Transaction processing aborted')
    || decoded.includes('transaction processing aborted');
}

/** Check if an error message indicates an invalid zkLogin session (not retryable) */
function isZkLoginProofError(msg: string): boolean {
  const decoded = decodeMsg(msg);
  return decoded.includes('Groth16 proof verify failed')
    || decoded.includes('Groth16');
}

export class SponsoredTransactionService {
  private client: SuiGrpcClient;
  private sponsorApiPath: string;

  constructor(client: SuiGrpcClient, sponsorApiUrl?: string) {
    this.client = client;
    // Extract base URL (strip /transaction suffix if present from old config)
    const url = sponsorApiUrl || '/api/sponsor/transaction';
    const baseUrl = url.replace(/\/transaction$/, '');
    // httpClient baseURL is '/api', so strip '/api' prefix for relative paths.
    // Absolute URLs (e.g. external sponsor backends) are preserved as-is;
    // axios will use them directly instead of prepending baseURL.
    this.sponsorApiPath = baseUrl.startsWith('/api') ? baseUrl.slice(4) : baseUrl;
  }

  // ---------------------------------------------------------------------------
  // 新流程（Shinami Gas Station）：
  // 1. POST /api/sui/action/build → 获取 tx_kind (base64 TransactionKind BCS)
  // 2. POST /api/sponsor/transaction { tx_kind, sender } → 获取 Shinami 赞助的
  //    tx_bytes + gas signature
  // 3. zkLogin 签名 tx_bytes
  // 4. 提交双签名交易到 Sui
  // ---------------------------------------------------------------------------

  /**
   * 调用后端 /api/sui/action/build 构建 TransactionKind。
   * 返回 base64 编码的 tx_kind。
   */
  async buildActionTxKind(request: BuildActionRequest): Promise<string> {
    const response = await httpClient.post<BuildActionResponse>('/sui/action/build', request);

    const data = response.data;
    if (!data.tx_kind) {
      throw new Error('Missing tx_kind in build action response');
    }
    return data.tx_kind;
  }

  /**
   * 构建、签名并提交赞助交易，在 gas coin 过期时自动重试。
   *
   * Shinami Gas Station 流程：
   * 1. 将 tx_kind + sender 发送到后端代理 → Shinami 返回 sponsored txBytes + gas sig
   * 2. 用 zkLogin ephemeral key 签名 sponsored txBytes
   * 3. 提交双签名交易
   *
   * 如果提交失败并返回 "Could not find the referenced object"（gas coin 过期）
   * 或超时错误，交易会重新请求赞助并重新提交。
   *
   * @param txKindB64 base64 编码的 BCS 序列化 TransactionKind 字节
   * @param verbose 是否输出详细诊断日志（zkLogin 地址验证等）
   * @returns 交易结果
   */
  private async _buildSignSubmitWithRetry(
    txKindB64: string,
    verbose: boolean = false,
  ): Promise<SponsoredTransactionResult> {
    const zkLoginManager = getZkLoginSessionManager();
    const session = zkLoginManager.getSession();
    if (!session) {
      return { digest: '', success: false, error: 'No zkLogin session. Please login first.' };
    }

    let lastError = '';

    for (let attempt = 1; attempt <= MAX_GAS_RETRY_ATTEMPTS; attempt++) {
      // Step 1: Request sponsorship from Shinami (via backend proxy)
      // Shinami selects fresh gas coins, so no need to fetch gas info separately.
      const sponsorResponse = await this.requestSponsorSignature({
        tx_kind: txKindB64,
        sender: session.address,
      });

      if (!sponsorResponse.signature || !sponsorResponse.tx_bytes) {
        return { digest: '', success: false, error: 'Sponsor signature request failed' };
      }

      const txBytes = fromB64(sponsorResponse.tx_bytes);

      // Step 2: Sign the sponsored txBytes with zkLogin ephemeral key
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

      // Step 2a (verbose only, first attempt): pre-verify zkLogin signature
      if (verbose && attempt === 1) {
        const { computeZkLoginAddressFromSeed } = await import('@mysten/sui/zklogin');
        const computedAddress = computeZkLoginAddressFromSeed(
          addressSeed,
          session.decodedJwt.iss,
          false,
        );
        console.log('[SigningRequest] zkLogin diagnostic:', {
          sessionAddress: session.address,
          computedAddressFromSeed: computedAddress,
          addressMatch: session.address === computedAddress,
          maxEpoch: session.maxEpoch,
          userSalt: session.userSalt,
          sub: session.decodedJwt.sub,
          aud: session.decodedJwt.aud,
          iss: session.decodedJwt.iss,
          addressSeed: addressSeed.toString(),
          zkProofKeys: Object.keys(session.zkProof),
          proofPointsA: session.zkProof.proofPoints?.a?.length,
          proofPointsB: session.zkProof.proofPoints?.b?.length,
          proofPointsC: session.zkProof.proofPoints?.c?.length,
          issBase64Value: session.zkProof.issBase64Details?.value,
          headerBase64Length: session.zkProof.headerBase64?.length,
          ephemeralPubKey: session.ephemeralKeyPair.getPublicKey().toSuiPublicKey(),
          sponsorTxDigest: sponsorResponse.tx_digest,
        });

        try {
          const verifyResult = await this.client.core.verifyZkLoginSignature({
            bytes: sponsorResponse.tx_bytes,
            signature: zkLoginSignature,
            intentScope: 'TransactionData',
            address: session.address,
          });
          console.log('[SigningRequest] zkLogin signature verify result:', verifyResult);
          if (!verifyResult.success) {
            const errs = verifyResult.errors || [];
            if (errs.some((e) => e.includes('Groth16') || e.includes('proof'))) {
              console.warn('[SigningRequest] ZK proof invalid (pre-verify), clearing session. Please re-login.');
              zkLoginManager.clearSession();
              return {
                digest: '',
                success: false,
                error: 'zkLogin session invalid (ZK proof rejected). Please re-login.',
              };
            }
            console.error('[SigningRequest] zkLogin signature verification FAILED:', errs);
          }
        } catch (verifyErr) {
          console.error('[SigningRequest] zkLogin signature verify call threw:', verifyErr);
        }
      }

      // Step 3: Submit dual-signed transaction
      if (verbose) {
        console.log('[SigningRequest] Submitting tx with signatures:', {
          zkLoginSigLength: zkLoginSignature.length,
          sponsorSigLength: sponsorResponse.signature.length,
          txBytesLength: txBytes.length,
          sponsorTxDigest: sponsorResponse.tx_digest,
          attempt,
        });
      }

      try {
        const result = await this.client.executeTransaction({
          transaction: txBytes,
          signatures: [zkLoginSignature, sponsorResponse.signature],
          include: {
            effects: true,
          },
        });

        if (result.$kind === 'FailedTransaction') {
          const failedTx = result.FailedTransaction!;
          const failedMsg = failedTx.effects?.status?.error?.message || 'Transaction failed';
          if (isZkLoginProofError(failedMsg)) {
            console.warn('[SigningRequest] ZK proof invalid (FailedTransaction), clearing session. Please re-login.');
            zkLoginManager.clearSession();
            return {
              digest: failedTx.digest ?? '',
              success: false,
              error: 'zkLogin session invalid (ZK proof rejected). Please re-login.',
            };
          }
          return {
            digest: failedTx.digest ?? '',
            success: false,
            error: failedMsg,
          };
        }

        const tx = result.Transaction!;
        const success = tx.effects?.status?.success === true;
        const errorMsg = success ? undefined : (tx.effects?.status?.error?.message || 'Unknown error');

        // If the zkLogin proof failed on-chain, the session is irrecoverably invalid.
        if (!success && errorMsg && isZkLoginProofError(errorMsg)) {
          console.warn('[SigningRequest] ZK proof invalid, clearing session. Please re-login.');
          zkLoginManager.clearSession();
          return {
            digest: tx.digest ?? '',
            success: false,
            error: 'zkLogin session invalid (ZK proof rejected). Please re-login.',
          };
        }

        return {
          digest: tx.digest ?? '',
          success,
          error: errorMsg,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Unknown error';

        // Groth16 errors are not retryable — session is invalid
        if (isZkLoginProofError(msg)) {
          console.warn('[SigningRequest] ZK proof invalid (catch), clearing session. Please re-login.');
          zkLoginManager.clearSession();
          return { digest: '', success: false, error: 'zkLogin session invalid (ZK proof rejected). Please re-login.' };
        }

        lastError = msg;

        // Retryable: stale gas coin ("Could not find the referenced object") or timeout.
        // Re-request sponsorship on the next attempt — Shinami will select fresh gas coins.
        if (isRetryableError(msg) && attempt < MAX_GAS_RETRY_ATTEMPTS) {
          console.warn(
            `[SponsoredTx] Attempt ${attempt}/${MAX_GAS_RETRY_ATTEMPTS} failed (retryable), ` +
            `re-requesting sponsorship: ${msg}`,
          );
          // Brief delay to let the gas coin settle before retrying
          await new Promise((r) => setTimeout(r, 500 * attempt));
          continue;
        }

        console.error('[SponsoredTx] Failed:', msg);
        return { digest: '', success: false, error: msg };
      }
    }

    return { digest: '', success: false, error: lastError || 'Transaction failed after retries' };
  }

  /**
   * 执行赞助的游戏操作（通过后端构建 PTB）。
   *
   * 使用 Shinami Gas Station 进行 gas 赞助，在 gas coin 过期时自动重试。
   *
   * @param request 游戏操作参数（action, table_id, seat_index, 以及 join_and_shuffle_verified 需要的加密参数）
   * @returns 交易结果
   */
  async executeSponsoredAction(request: BuildActionRequest): Promise<SponsoredTransactionResult> {
    const zkLoginManager = getZkLoginSessionManager();
    const session = zkLoginManager.getSession();

    if (!session) {
      return { digest: '', success: false, error: 'No zkLogin session. Please login first.' };
    }

    try {
      // Validate session epoch before doing anything — expired zkLogin proofs
      // fail on-chain with "Groth16 proof verify failed".
      await zkLoginManager.ensureSessionValid();

      // Build TransactionKind via backend
      const txKindB64 = await this.buildActionTxKind(request);

      // Build, sign, and submit with automatic retry on stale gas coins
      return this._buildSignSubmitWithRetry(txKindB64);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      console.error('[SponsoredAction] Failed:', msg);
      if (isZkLoginProofError(msg)) {
        zkLoginManager.clearSession();
        return { digest: '', success: false, error: 'zkLogin session invalid (ZK proof rejected). Please re-login.' };
      }
      return { digest: '', success: false, error: msg };
    }
  }

  /**
   * 执行来自后端 socket `action_signing_request` 事件的签名请求。
   *
   * 使用 Shinami Gas Station 进行 gas 赞助，在 gas coin 过期时自动重试。
   *
   * @param txKindB64 base64 编码的 BCS 序列化 TransactionKind 字节
   * @returns 交易结果
   */
  async executeFromSigningRequest(txKindB64: string): Promise<SponsoredTransactionResult> {
    const zkLoginManager = getZkLoginSessionManager();
    const session = zkLoginManager.getSession();

    if (!session) {
      return { digest: '', success: false, error: 'No zkLogin session. Please login first.' };
    }

    try {
      // Validate session epoch before doing anything — expired zkLogin proofs
      // fail on-chain with "Groth16 proof verify failed".
      await zkLoginManager.ensureSessionValid();

      // Build, sign, and submit with automatic retry on stale gas coins
      return this._buildSignSubmitWithRetry(txKindB64, true);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      console.error('[SigningRequest] Failed:', msg);
      if (isZkLoginProofError(msg)) {
        zkLoginManager.clearSession();
        return { digest: '', success: false, error: 'zkLogin session invalid (ZK proof rejected). Please re-login.' };
      }
      return { digest: '', success: false, error: msg };
    }
  }

  /**
   * 执行一个预先构建好的 Transaction 对象的赞助交易。
   *
   * 将 Transaction 转换为 gasless transaction（仅 TransactionKind），然后通过 Shinami 赞助。
   *
   * @param transaction 预先构建好的 Transaction 对象（无需设置 gas 信息）
   * @returns 交易结果
   */
  async executeSponsoredGameAction(transaction: Transaction): Promise<SponsoredTransactionResult> {
    const zkLoginManager = getZkLoginSessionManager();
    const session = zkLoginManager.getSession();

    if (!session) {
      return { digest: '', success: false, error: 'No zkLogin session. Please login first.' };
    }

    try {
      await zkLoginManager.ensureSessionValid();

      // Build gasless TransactionKind (no gas info) — equivalent to Shinami's
      // buildGaslessTransaction helper, but inlined to avoid the dependency.
      const txKindBytes = await transaction.build({
        client: this.client as any,
        onlyTransactionKind: true,
      });
      const txKind = toB64(txKindBytes);

      return this._buildSignSubmitWithRetry(txKind);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      console.error('[SponsoredTx] Failed:', msg);
      if (isZkLoginProofError(msg)) {
        zkLoginManager.clearSession();
        return { digest: '', success: false, error: 'zkLogin session invalid (ZK proof rejected). Please re-login.' };
      }
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

  // Request sponsorship from Shinami Gas Station (via backend proxy)
  // POST /api/sponsor/transaction { tx_kind, sender, gas_budget? }
  // → { tx_bytes, signature, tx_digest }
  private async requestSponsorSignature(request: SponsorTransactionRequest): Promise<SponsorTransactionResponse> {
    const response = await httpClient.post<SponsorTransactionResponse>(
      `${this.sponsorApiPath}/transaction`,
      request
    );
    return response.data;
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
