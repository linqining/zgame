import { useEffect } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { Socket } from 'socket.io-client';
import type { Card, CryptoEvent, GameMessage, Table } from '../../types/game';
import {
  TABLE_JOINED,
  TABLE_LEFT,
  TABLE_UPDATED,
  SHUFFLE_NOTICE,
  SHUFFLE_SUBMIT,
  RECONSTRUCT_NOTICE,
  RECONSTRUCT_SUBMIT,
  RECONSTRUCT_RESULT,
  REVEAL_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
  REDEAL_NOTICE,
  REDEAL_RESULT,
  REDEAL_REQUEST,
  CRYPTO_EVENT,
  ACTION_SIGNING_REQUEST,
} from '../../pokergame/actions';
import { getSponsoredTransactionService } from '../../sui/sponsoredTx';
import {
  ShuffleNoticeData,
  RevealNoticeData,
  HandRevealResultData,
  CommunityRevealResultData,
  ReconstructNoticeData,
  ReconstructSubmitPayload,
  TableUpdatedPayload,
  TableJoinedPayload,
  TableLeftPayload,
  HandRevealReturn,
  ShuffleHandleResult,
} from './gameInternal';

export interface UseGameSocketParams {
  socket: Socket | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  setCurrentTable: (table: Table | null) => void;
  setMessages: Dispatch<SetStateAction<GameMessage[]>>;
  setDecryptedHandCards: Dispatch<SetStateAction<string[]>>;
  setCommunityCards: Dispatch<SetStateAction<Card[]>>;
  setKickNotification: (notification: string | null) => void;
  setCryptoEvents: Dispatch<SetStateAction<CryptoEvent[]>>;
  isUnmountingRef: MutableRefObject<boolean>;
  pkHex: string | null;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  handleShuffleNotice: (data: ShuffleNoticeData) => Promise<ShuffleHandleResult | null>;
  handleRevealNotice: (data: RevealNoticeData) => Promise<void>;
  handleReconstructNotice: (data: ReconstructNoticeData) => Promise<ReconstructSubmitPayload | void>;
  handleHandRevealResult: (data: HandRevealResultData) => HandRevealReturn | null;
  handleCommunityRevealResult: (data: CommunityRevealResultData) => void;
}

/**
 * 将后端发来的踢出 reason 文本翻译为面向用户的中文提示。
 * 已知关键词（shuffle/reveal/reconstruct + timeout）会被映射为简洁中文，
 * 其余文本原样保留，最终格式为 "你因 … 被移出牌桌"。
 */
function translateKickReason(reason: string): string {
  const lower = reason.toLowerCase();
  let core: string;
  if (lower.includes('shuffle')) {
    core = 'shuffle 超时';
  } else if (lower.includes('reveal')) {
    core = 'reveal 超时';
  } else if (lower.includes('reconstruct')) {
    core = 'reconstruct 超时';
  } else {
    core = reason;
  }
  return `你因 ${core} 被移出牌桌`;
}

export const useGameSocket = (params: UseGameSocketParams): void => {
  const {
    socket,
    addMessage,
    currentTableRef,
    setCurrentTable,
    setMessages,
    setDecryptedHandCards,
    setCommunityCards,
    setKickNotification,
    setCryptoEvents,
    isUnmountingRef,
    pkHex,
    leaveTable,
    handleShuffleNotice,
    handleRevealNotice,
    handleReconstructNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
  } = params;

  useEffect(() => {
    const onUnload = () => leaveTable(false, pkHex || undefined, true);
    window.addEventListener('unload', onUnload);
    window.addEventListener('close', onUnload);

    if (socket) {
      socket.on(TABLE_UPDATED, ({ table, message, from }: TableUpdatedPayload) => {
        console.log(TABLE_UPDATED, table, message, from);
        setCurrentTable(table);
        console.log("table updated:", table);
        message && addMessage(message);
      });

      socket.on(TABLE_JOINED, ({ table, message, from }: TableJoinedPayload) => {
        console.log(TABLE_JOINED, table, message, from);
        console.log("table joined:", table);
        setCurrentTable(table);
      });

      socket.on(TABLE_LEFT, ({ tables, tableId, reason }: TableLeftPayload) => {
        console.log(TABLE_LEFT, tables, tableId, reason);
        setCurrentTable(null);
        // loadUser(localStorage.token);
        setMessages([]);
        setDecryptedHandCards([]);
        setCommunityCards([]);
        if (reason && reason.trim()) {
          setKickNotification(translateKickReason(reason));
        }
      });

      socket.on(SHUFFLE_NOTICE, async (data: ShuffleNoticeData) => {
        // 新一手洗牌开始，清空上一手的公共牌
        setCommunityCards([]);
        const result = await handleShuffleNotice(data);
        if (result) {
          console.log('SHUFFLE_NOTICE shuffle proof', result.shuffleResult.shuffle_proof);
          socket.emit(SHUFFLE_SUBMIT, {
            table_id: result.tableId,
            pk_hex: result.pkHex,
            output_cards: result.shuffleResult.output_cards,
            shuffle_proof: result.shuffleResult.shuffle_proof,
          });
          console.log(SHUFFLE_SUBMIT, result);
          addMessage(`Shuffle submitted (${result.shuffleResult.output_cards.length} cards)`);
        }
      });

      socket.on(REVEAL_NOTICE, (data: RevealNoticeData) => {
        handleRevealNotice(data);
      });

      socket.on(RECONSTRUCT_NOTICE, async (data: ReconstructNoticeData) => {
        const result = await handleReconstructNotice(data);
        if (result) {
          socket.emit(RECONSTRUCT_SUBMIT, result);
        }
      });

      socket.on(RECONSTRUCT_RESULT, (data: { expelled?: boolean }) => {
        console.log(RECONSTRUCT_RESULT, data);
        if (data?.expelled) {
          addMessage('Player expelled by vote');
        } else {
          addMessage('construct vote timed out');
        }
      });

      socket.on(HAND_REVEAL_RESULT, (data: HandRevealResultData) => {
        const redealInfo = handleHandRevealResult(data);
        if (redealInfo) {
          socket.emit(REDEAL_REQUEST, {
            tableId: currentTableRef.current?.id,
            playerPk: redealInfo.playerPk,
            failedCardIndices: redealInfo.failedCardIndices,
          });
          addMessage(`Requesting redeal for ${redealInfo.failedCardIndices?.length || 0} failed cards...`);
        }
      });

      socket.on(COMMUNITY_REVEAL_RESULT, (data: CommunityRevealResultData) => {
        handleCommunityRevealResult(data);
      });

      socket.on(REDEAL_NOTICE, (data: RevealNoticeData) => {
        console.log(REDEAL_NOTICE, data);
        handleRevealNotice(data);
      });

      socket.on(REDEAL_RESULT, (data: HandRevealResultData) => {
        const redealInfo = handleHandRevealResult(data);
        if (redealInfo) {
          addMessage(`Redeal decryption still failed for ${redealInfo.failedCardIndices?.length || 0} cards`);
        } else {
          addMessage('Redeal successful, new cards decrypted');
        }
      });

      // ZK 密码学事件：收集最近 100 条，供主牌桌可视化面板消费
      socket.on(CRYPTO_EVENT, (data: CryptoEvent) => {
        console.log(CRYPTO_EVENT, data);
        setCryptoEvents((prev) => {
          const next = [...prev, data];
          // 仅保留最近 100 条，避免无界增长
          return next.length > 100 ? next.slice(next.length - 100) : next;
        });
      });

      // 后端在 on-chain 模式下推送的签名请求：直接用 tx_kind_b64 走 sponsored 签名流程
      socket.on(ACTION_SIGNING_REQUEST, (data: { action?: string; tx_kind_b64?: string }) => {
        console.log(ACTION_SIGNING_REQUEST, data);
        // leave_with_proof_verified 由 standUp() 直接处理（等待签名完成后才离开）
        if (data?.action === 'leave_with_proof_verified') {
          return;
        }
        if (!data?.tx_kind_b64) {
          console.error('[ActionSigningRequest] Missing tx_kind_b64 in payload', data);
          return;
        }
        getSponsoredTransactionService()
          .executeFromSigningRequest(data.tx_kind_b64)
          .then((result) => {
            if (result.success) {
              console.log('[ActionSigningRequest] Tx executed:', result.digest);
            } else {
              console.error('[ActionSigningRequest] Tx failed:', result.error);
            }
          })
          .catch((err) => {
            console.error('[ActionSigningRequest] Execution error:', err);
          });
      });
    }
    return () => {
      window.removeEventListener('unload', onUnload);
      window.removeEventListener('close', onUnload);
      socket?.off(TABLE_UPDATED);
      socket?.off(TABLE_JOINED);
      socket?.off(TABLE_LEFT);
      socket?.off(SHUFFLE_NOTICE);
      socket?.off(REVEAL_NOTICE);
      socket?.off(RECONSTRUCT_NOTICE);
      socket?.off(RECONSTRUCT_RESULT);
      socket?.off(HAND_REVEAL_RESULT);
      socket?.off(COMMUNITY_REVEAL_RESULT);
      socket?.off(REDEAL_NOTICE);
      socket?.off(REDEAL_RESULT);
      socket?.off(CRYPTO_EVENT);
      socket?.off(ACTION_SIGNING_REQUEST);
      // Only leave table on actual component unmount, not on socket disconnect
      // Socket disconnect will trigger reconnect via FETCH_LOBBY_INFO
      if (isUnmountingRef.current) {
        leaveTable(true, pkHex || undefined, true);
      }
    };
  }, [socket, handleShuffleNotice, handleRevealNotice, handleReconstructNotice, handleHandRevealResult, handleCommunityRevealResult]); // eslint-disable-line react-hooks/exhaustive-deps
};
