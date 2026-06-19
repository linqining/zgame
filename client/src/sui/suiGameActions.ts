/**
 * Sui 链上游戏操作辅助模块
 *
 * 将 WASM 加密结果转换为 Move 合约期望的字节格式，
 * 并通过 SponsoredTransactionService 提交到 Sui 链上。
 */

import {
  getSponsoredTransactionService,
  type BuildActionRequest,
  type SponsoredTransactionResult,
} from './sponsoredTx';
import { toB64 } from './utils';

/**
 * 提交 join_and_shuffle_verified 操作到 Sui 链上（赞助交易）。
 *
 * @param suiTableId 链上 Table 对象 ID
 * @param seatIndex 座位索引
 * @param coinObjectId 买入用的 SUI Coin 对象 ID (hex)，合约已改为接收 Coin<SUI>
 * @param joinResultJson WASM join_game_and_shuffle 返回的 JSON 字符串
 * @returns 交易结果
 */
export async function submitJoinAndShuffle(
  suiTableId: string,
  seatIndex: number,
  coinObjectId: string,
  joinResultJson: string,
): Promise<SponsoredTransactionResult> {
  // 动态导入 WASM 序列化函数（避免在模块加载时就依赖 WASM 初始化）
  const { serialize_join_and_shuffle_to_move_bytes } = await import('@linqining/client-wasm');

  // 将 WASM 输出的 hex JSON 转换为 Move 合约期望的 flat bytes (base64)
  const moveBytesStr = serialize_join_and_shuffle_to_move_bytes(joinResultJson);
  const moveBytes = typeof moveBytesStr === 'string' ? JSON.parse(moveBytesStr) : moveBytesStr;

  const request: BuildActionRequest = {
    action: 'join_and_shuffle_verified',
    table_id: suiTableId,
    seat_index: seatIndex,
    coin_object_id: coinObjectId,
    pk: moveBytes.pk,                       // base64(48 bytes)
    pk_ownership_proof: moveBytes.pk_ownership_proof,  // base64(80 bytes)
    output_cards: moveBytes.output_cards,   // base64(96*N bytes)
    remask_proof_bytes: moveBytes.remask_proof_bytes,  // base64(...)
    shuffle_proof_bytes: moveBytes.shuffle_proof_bytes, // base64(...)
  };

  const service = getSponsoredTransactionService();
  return service.executeSponsoredAction(request);
}

/**
 * 提交 fold 操作到 Sui 链上（赞助交易）。
 */
export async function submitFold(
  suiTableId: string,
  seatIndex: number,
): Promise<SponsoredTransactionResult> {
  const request: BuildActionRequest = {
    action: 'fold',
    table_id: suiTableId,
    seat_index: seatIndex,
  };
  const service = getSponsoredTransactionService();
  return service.executeSponsoredAction(request);
}

/**
 * 提交 check 操作到 Sui 链上（赞助交易）。
 */
export async function submitCheck(
  suiTableId: string,
  seatIndex: number,
): Promise<SponsoredTransactionResult> {
  const request: BuildActionRequest = {
    action: 'check',
    table_id: suiTableId,
    seat_index: seatIndex,
  };
  const service = getSponsoredTransactionService();
  return service.executeSponsoredAction(request);
}

/**
 * 提交 call 操作到 Sui 链上（赞助交易）。
 */
export async function submitCall(
  suiTableId: string,
  seatIndex: number,
): Promise<SponsoredTransactionResult> {
  const request: BuildActionRequest = {
    action: 'call',
    table_id: suiTableId,
    seat_index: seatIndex,
  };
  const service = getSponsoredTransactionService();
  return service.executeSponsoredAction(request);
}

/**
 * 提交 raise 操作到 Sui 链上（赞助交易）。
 *
 * @param totalBet 本次加注后的总下注额
 */
export async function submitRaise(
  suiTableId: string,
  seatIndex: number,
  totalBet: number,
): Promise<SponsoredTransactionResult> {
  const request: BuildActionRequest = {
    action: 'raise',
    table_id: suiTableId,
    seat_index: seatIndex,
    total_bet: totalBet,
  };
  const service = getSponsoredTransactionService();
  return service.executeSponsoredAction(request);
}

/**
 * 提交 leave_with_proof_verified 操作到 Sui 链上（赞助交易）。
 *
 * 参考 `submitJoinAndShuffle`，通过同步 HTTP API (`/api/sui/action/build`)
 * 获取 TransactionKind，再由 SponsoredTransactionService 完成 sponsor + zkLogin
 * 签名 + 提交。
 *
 * @param suiTableId 链上 Table 对象 ID
 * @param seatIndex 座位索引
 * @param outputCardsJson WASM leave_game 返回的 output_cards JSON 字符串
 *                        （ElGamalCiphertext 数组）
 * @param leaveProofJson WASM leave_game 返回的 leave_proof JSON 字符串
 * @returns 交易结果
 */
export async function submitLeave(
  suiTableId: string,
  seatIndex: number,
  outputCardsJson: string,
  leaveProofJson: string,
  hasShuffled: boolean,
): Promise<SponsoredTransactionResult> {
  // 动态导入 WASM 序列化函数（返回 Uint8Array，需自行 base64 编码）
  const { serialize_ciphertexts_to_move_bytes, serialize_leave_proof_to_move_bytes } =
    await import('@linqining/client-wasm');

  const service = getSponsoredTransactionService();

  // 根据玩家是否已完成洗牌，仅提交对应的 leave 交易。
  // 同时提交两个交易会导致：先执行的交易清空座位，后执行的交易因 ESeatEmpty 失败。
  // - 已洗牌 → leave_with_proof_verified（需要 completed_players 包含 seat_index）
  // - 未洗牌 → leave_table（需要 completed_players 不包含 seat_index）
  if (hasShuffled) {
    const outputCardsBytes = serialize_ciphertexts_to_move_bytes(outputCardsJson);
    const leaveProofBytes = serialize_leave_proof_to_move_bytes(leaveProofJson);
    const proofRequest: BuildActionRequest = {
      action: 'leave_with_proof_verified',
      table_id: suiTableId,
      seat_index: seatIndex,
      output_cards: toB64(outputCardsBytes),
      leave_proof_bytes: toB64(leaveProofBytes),
    };
    return service.executeSponsoredAction(proofRequest);
  } else {
    const simpleRequest: BuildActionRequest = {
      action: 'leave_table',
      table_id: suiTableId,
      seat_index: seatIndex,
    };
    return service.executeSponsoredAction(simpleRequest);
  }
}
