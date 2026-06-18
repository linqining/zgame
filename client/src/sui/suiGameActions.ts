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

/**
 * 提交 join_and_shuffle 操作到 Sui 链上（赞助交易）。
 *
 * @param suiTableId 链上 Table 对象 ID
 * @param seatIndex 座位索引
 * @param buyIn 买入金额
 * @param joinResultJson WASM join_game_and_shuffle 返回的 JSON 字符串
 * @returns 交易结果
 */
export async function submitJoinAndShuffle(
  suiTableId: string,
  seatIndex: number,
  buyIn: number,
  joinResultJson: string,
): Promise<SponsoredTransactionResult> {
  // 动态导入 WASM 序列化函数（避免在模块加载时就依赖 WASM 初始化）
  const { serialize_join_and_shuffle_to_move_bytes } = await import('@linqining/client-wasm');

  // 将 WASM 输出的 hex JSON 转换为 Move 合约期望的 flat bytes (base64)
  const moveBytesStr = serialize_join_and_shuffle_to_move_bytes(joinResultJson);
  const moveBytes = typeof moveBytesStr === 'string' ? JSON.parse(moveBytesStr) : moveBytesStr;

  const request: BuildActionRequest = {
    action: 'join_and_shuffle',
    table_id: suiTableId,
    seat_index: seatIndex,
    buy_in: buyIn,
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
