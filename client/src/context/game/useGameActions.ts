import { useContext, type MutableRefObject } from 'react';
import type { NavigateFunction } from 'react-router-dom';
import type { Socket } from 'socket.io-client';
import { compute_aggregate_key } from '@linqining/client-wasm';
import type { WasmClientPlayer } from '@linqining/client-wasm';
import {
  CALL,
  CHECK,
  FOLD,
  JOIN_TABLE,
  LEAVE_TABLE,
  RAISE,
  REBUY,
  SIT_DOWN_V2,
  STAND_UP,
  SITTING_OUT,
  SITTING_IN,
  RECONSTRUCT_INITIATE,
  TABLE_UPDATED,
} from '../../pokergame/actions';
import { getToken } from '../../helpers/getToken';
import type { Table, Seat } from '../../types/game';
import { JoinAndShuffleResult, TableUpdatedPayload, wrapCryptoOp } from './gameInternal';
import { defaultClient } from '../../sui/config';
import { submitLeave } from '../../sui/suiGameActions';
import authContext from '../../context/auth/authContext';

export interface UseGameActionsParams {
  socket: Socket | null;
  navigate: NavigateFunction;
  playerKeys: WasmClientPlayer | null;
  pkHex: string | null;
  getPlayerKeys: () => WasmClientPlayer | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  seatId: number | null;
  isPlayerSeated: boolean;
}

export interface UseGameActionsReturn {
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
  rebuy: (tableId: string, seatId: number, amount: number) => void;
  standUp: () => Promise<void>;
  fold: () => void;
  check: () => void;
  call: () => void;
  raise: (amount: number) => void;
  sittingOut: () => void;
  sittingIn: () => void;
  expelInitiate: (tableId: string, targetPlayerPk: string) => void;
}

export const useGameActions = (params: UseGameActionsParams): UseGameActionsReturn => {
  const {
    socket,
    navigate,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    seatId,
    isPlayerSeated,
  } = params;

  const { walletAddress } = useContext(authContext)!;

  /**
   * 查找余额足够的 SUI Coin 对象用于链上买入。
   * 合约已改为接收 Coin<SUI>，需要前端提供 coin object id。
   * @param chipsAmount 筹码数量（1 SUI = 10000 chips → 1 chip = 100_000 MIST）
   * @returns coin object id 或 null（未找到足够余额的 coin）
   */
  const findSuiCoinForBuyin = async (chipsAmount: number): Promise<string | null> => {
    if (!walletAddress) return null;
    const requiredMist = BigInt(chipsAmount) * 100_000n; // MIST_PER_CHIP
    try {
      const resp = await defaultClient.listCoins({ owner: walletAddress, limit: 50 });
      // 找到余额足够的单个 coin
      const coin = resp.objects.find(c => BigInt(c.balance) >= requiredMist);
      if (coin) return coin.objectId;
      // 如果没有单个 coin 足够，可能需要合并 — 暂不支持，返回 null
      console.warn('[findSuiCoinForBuyin] no single coin has enough balance, required MIST:', requiredMist.toString());
      return null;
    } catch (err) {
      console.error('[findSuiCoinForBuyin] listCoins failed:', err);
      return null;
    }
  };

  const joinTable = (tableId: number, pkHex: string) => {
    console.log(JOIN_TABLE, { tableId, pkHex });
    socket?.emit(JOIN_TABLE, { tableId, pkHex });
  };

  const leaveTable = async (shouldNavigate = true, pkHex?: string, fireAndForget = false) => {
    if (isPlayerSeated) {
      if (fireAndForget) {
        // 页面卸载/组件卸载场景：无法等待异步签名流程，直接触发
        standUp().catch(e => console.error('[leaveTable] standUp failed (fire-and-forget):', e));
      } else {
        try {
          await standUp();
        } catch (e) {
          const err = e as Error;
          console.error('[leaveTable] standUp failed:', e);
          addMessage(`Failed to leave table: ${err.message || e}`);
          return;
        }
      }
    }
    currentTableRef &&
      currentTableRef.current &&
      currentTableRef.current.id &&
      socket?.emit(LEAVE_TABLE, { tableId: currentTableRef.current.id, pkHex: pkHex || '' });
    if (shouldNavigate) navigate('/');
  };

  const sitDown = async (tableId: string, seatId: number, amount: number) => {
    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.error('[SitDown] No player keys available');
      addMessage('Cannot sit down: no player keys');
      return;
    }
    if (!pkHex) {
      console.error('[SitDown] No pkHex available');
      addMessage('Cannot sit down: no public key');
      return;
    }

    const table = currentTableRef.current;
    if (!table) {
      console.error('[SitDown] No current table');
      addMessage('Cannot sit down: no table data');
      return;
    }

    const deckEncrypted = table.shuffleState?.deck_encrypted || table.deck?.cards;
    if (!deckEncrypted || deckEncrypted.length === 0) {
      console.error('[SitDown] No deck_encrypted available');
      addMessage('Cannot sit down: no encrypted deck');
      return;
    }
    try {
      const token = getToken();
      if (!token) {
        console.error('[SitDown] No auth token available');
        addMessage('Cannot sit down: please connect your wallet first');
        return;
      }

      // 查找买入用的 SUI Coin 对象（合约已改为接收 Coin<SUI>）
      const coinObjectId = await findSuiCoinForBuyin(amount);
      if (!coinObjectId) {
        console.error('[SitDown] No suitable SUI coin found for buy-in');
        addMessage('Cannot sit down: no SUI coin with enough balance. Try merging coins or requesting faucet SUI.');
        return;
      }
      console.log('[SitDown] using coin object:', coinObjectId, 'for buy-in amount:', amount);

      const pkHexes = (Object.values(table.seats) || [])
        .filter((p: Seat) => p.player && p.player.pkHex && p.player.pkHex !== pkHex).map((p: Seat) => p.player!.pkHex);
      const pkHexesJson = JSON.stringify(pkHexes);
      const aggPkHex = compute_aggregate_key(pkHexesJson);

      const deckEncryptedJson = JSON.stringify(deckEncrypted);
      console.log('SIT_DOWN_V2', tableId, seatId, amount, pkHex, aggPkHex);
      const joinResultRaw = wrapCryptoOp(() => {
        const result = keys.join_game_and_shuffle(deckEncryptedJson, aggPkHex);
        if (!result) throw new Error('join_game_and_shuffle returned null');
        return result;
      }, 'join_game_and_shuffle') as string | object;
      const joinResult = typeof joinResultRaw === 'string' ? JSON.parse(joinResultRaw) : joinResultRaw as JoinAndShuffleResult;

      const maskAndShuffleRound = {
        mask_cards: joinResult.mask_and_shuffle_round.mask_cards,
        output_cards: joinResult.mask_and_shuffle_round.output_cards,
        remask_proof: joinResult.mask_and_shuffle_round.remask_proof,
        shuffle_proof: joinResult.mask_and_shuffle_round.shuffle_proof,
      };
      const pkProof = joinResult.pk_ownership_proof;
      console.log('SIT_DOWN_V2', tableId, seatId, amount, pkHex, pkProof, maskAndShuffleRound, keys.get_pk_hex(), getToken());
      socket?.emit(SIT_DOWN_V2, { token, tableId, seatId, amount, pkHex, pkProof, maskAndShuffleRound, coinObjectId });
      addMessage('Joined table and shuffled successfully');
    } catch (e) {
      const err = e as Error;
      console.error('[SitDown] join_and_shuffle failed:', e);
      addMessage(`Sit down failed: ${err.message || e}`);
    }
  };

  const rebuy = (tableId: string, seatId: number, amount: number) => {
    socket?.emit(REBUY, { tableId, seatId, amount });
  };

  const standUp = async () => {
    if (!currentTableRef.current) return;
    const table = currentTableRef.current;

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.error('[StandUp] No player keys available');
      return;
    }

    // 判断玩家是否已完成洗牌（PK 在 completed_players 中）
    // - 已洗牌 → leave_with_proof_verified（需要密码学证明）
    // - 未洗牌 → leave_table（简单离开，无需证明）
    const hasShuffled = !!(
      pkHex &&
      table.shuffleState?.completed_players?.includes(pkHex)
    );

    const deckEncrypted = table.shuffleState?.deck_encrypted || table.deck?.cards;

    // 链上模式：通过同步 HTTP API 获取 TransactionKind 并签名提交
    if (table.suiTableId && seatId != null) {
      if (!hasShuffled) {
        // 未洗牌玩家直接走 leave_table，无需生成 leave proof
        console.log('[StandUp] on-chain mode: submitting leave_table (player has not shuffled)');
        const result = await submitLeave(table.suiTableId, seatId, '', '', false);
        if (!result.success) {
          throw new Error(result.error || 'On-chain leave_table tx failed');
        }
        console.log('[StandUp] On-chain leave_table tx executed:', result.digest);
        socket?.emit(STAND_UP, { tableId: table.id, pkHex, leaveRound: null });
        return;
      }

      // 已洗牌玩家：需要 deck_encrypted 来生成 leave proof
      if (!deckEncrypted || deckEncrypted.length === 0) {
        console.warn('[StandUp] hasShuffled=true but no deck_encrypted, cannot generate leave proof');
        throw new Error('Cannot generate leave proof: deck_encrypted is empty');
      }

      console.log('[StandUp] on-chain mode: submitting leave_with_proof_verified');
      let outputCardsJson: string;
      let leaveProofJson: string;
      try {
        const deckEncryptedJson = JSON.stringify(deckEncrypted);
        const leaveResult = wrapCryptoOp(() => {
          const result = keys.leave_game(deckEncryptedJson);
          if (!result) throw new Error('leave_game returned null');
          return typeof result === 'string' ? JSON.parse(result) : result;
        }, 'leave_game') as { input_cards: unknown; output_cards: unknown; leave_proof: unknown };

        outputCardsJson = JSON.stringify(leaveResult.output_cards);
        leaveProofJson = JSON.stringify(leaveResult.leave_proof);
      } catch (e) {
        console.error('[StandUp] leave_game failed:', e);
        throw e;
      }

      const result = await submitLeave(table.suiTableId, seatId, outputCardsJson, leaveProofJson, true);
      if (!result.success) {
        throw new Error(result.error || 'On-chain leave_with_proof_verified tx failed');
      }
      console.log('[StandUp] On-chain leave_with_proof_verified tx executed:', result.digest);
      socket?.emit(STAND_UP, { tableId: table.id, pkHex, leaveRound: null });
      return;
    }

    // 离链模式：通过 socket 提交 leave 证明，等待后端验证并广播 TABLE_UPDATED
    if (!deckEncrypted || deckEncrypted.length === 0) {
      console.warn('[StandUp] No deck_encrypted, falling back to simple stand up');
      return;
    }

    let outputCardsJson: string;
    let leaveProofJson: string;
    let inputCards: unknown;
    try {
      const deckEncryptedJson = JSON.stringify(deckEncrypted);
      const leaveResult = wrapCryptoOp(() => {
        const result = keys.leave_game(deckEncryptedJson);
        if (!result) throw new Error('leave_game returned null');
        return typeof result === 'string' ? JSON.parse(result) : result;
      }, 'leave_game') as { input_cards: unknown; output_cards: unknown; leave_proof: unknown };

      inputCards = leaveResult.input_cards;
      outputCardsJson = JSON.stringify(leaveResult.output_cards);
      leaveProofJson = JSON.stringify(leaveResult.leave_proof);
    } catch (e) {
      const err = e as Error;
      console.error('[StandUp] leave_game failed:', e);
      throw err;
    }

    await new Promise<void>((resolve, reject) => {
      const STAND_UP_TIMEOUT_MS = 60_000;
      let settled = false;

      const cleanup = () => {
        clearTimeout(timer);
        socket?.off(TABLE_UPDATED, onTableUpdated);
        socket?.off('error', onError);
      };

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanup();
        console.warn('[StandUp] Timed out waiting for server response');
        reject(new Error('Stand up timed out waiting for server response'));
      }, STAND_UP_TIMEOUT_MS);

      // Off-chain mode: server removes player and broadcasts TABLE_UPDATED
      const onTableUpdated = (data: TableUpdatedPayload) => {
        if (!data?.table) return;
        // Check if this player is no longer seated
        const stillSeated = pkHex
          ? Object.values(data.table.seats || {}).some(
              (seat: Seat) => seat.player?.pkHex === pkHex,
            )
          : false;
        if (!stillSeated) {
          if (settled) return;
          settled = true;
          cleanup();
          console.log('[StandUp] Off-chain leave confirmed via TABLE_UPDATED');
          resolve();
        }
      };

      // Server emits error event on proof verification failure
      const onError = (data: { action?: string; msg?: string }) => {
        if (data?.action !== 'leave_with_proof_verified') return;
        if (settled) return;
        settled = true;
        cleanup();
        reject(new Error(data?.msg || 'Stand up failed on server'));
      };

      socket?.on(TABLE_UPDATED, onTableUpdated);
      socket?.on('error', onError);

      socket?.emit(STAND_UP, {
        tableId: table.id,
        pkHex,
        leaveRound: {
          input_cards: inputCards,
          output_cards: JSON.parse(outputCardsJson),
          leave_proof: JSON.parse(leaveProofJson),
        },
      });
    });
  };

  const fold = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(FOLD, currentTableRef.current.id);
  };

  const check = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(CHECK, currentTableRef.current.id);
  };

  const call = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(CALL, currentTableRef.current.id);
  };

  const raise = (amount: number) => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(RAISE, { tableId: currentTableRef.current.id, amount });
  };

  const sittingOut = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(SITTING_OUT, currentTableRef.current.id);
  };

  const sittingIn = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(SITTING_IN, currentTableRef.current.id);
  };

  const expelInitiate = (tableId: string, targetPlayerPk: string) => {
    socket?.emit(RECONSTRUCT_INITIATE, { tableId, targetPlayerPk });
  };

  return {
    joinTable,
    leaveTable,
    sitDown,
    rebuy,
    standUp,
    fold,
    check,
    call,
    raise,
    sittingOut,
    sittingIn,
    expelInitiate,
  };
};
