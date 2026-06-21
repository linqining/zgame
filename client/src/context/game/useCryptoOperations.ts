import { useCallback } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { Socket } from 'socket.io-client';
import type { WasmClientPlayer } from '@linqining/client-wasm';
import type { Card, Table } from '../../types/game';
import type { SubmitRevealToken } from '../../api/secretPokerClient';
import {
  SHUFFLE_NOTICE,
  SHUFFLE_SUBMIT,
  REVEAL_NOTICE,
  REVEAL_SUBMIT,
  RECONSTRUCT_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
} from '../../pokergame/actions';
import {
  ShuffleNoticeData,
  ShuffleResult,
  ShuffleHandleResult,
  RevealNoticeData,
  HandRevealResultData,
  HandRevealReturn,
  CommunityRevealResultData,
  ReconstructNoticeData,
  ReconstructSubmitPayload,
  ReconstructResult,
  wrapCryptoOp,
} from './gameInternal';

export interface UseCryptoOperationsParams {
  socket: Socket | null;
  playerKeys: WasmClientPlayer | null;
  pkHex: string | null;
  getPlayerKeys: () => WasmClientPlayer | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  setShuffleLoading: (value: boolean) => void;
  setRevealLoading: (value: boolean) => void;
  setDecryptedHandCards: Dispatch<SetStateAction<string[]>>;
  setCommunityCards: Dispatch<SetStateAction<Card[]>>;
  shuffleLoadingRef: MutableRefObject<boolean>;
  revealLoadingRef: MutableRefObject<boolean>;
}

export interface UseCryptoOperationsReturn {
  handleShuffleNotice: (data: ShuffleNoticeData) => Promise<ShuffleHandleResult | null>;
  handleRevealNotice: (data: RevealNoticeData) => Promise<void>;
  handleHandRevealResult: (data: HandRevealResultData) => HandRevealReturn | null;
  handleCommunityRevealResult: (data: CommunityRevealResultData) => void;
  handleReconstructNotice: (data: ReconstructNoticeData) => Promise<ReconstructSubmitPayload | void>;
}

export const useCryptoOperations = (
  params: UseCryptoOperationsParams,
): UseCryptoOperationsReturn => {
  const {
    socket,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    setShuffleLoading,
    setRevealLoading,
    setDecryptedHandCards,
    setCommunityCards,
    shuffleLoadingRef,
    revealLoadingRef,
  } = params;

  const handleShuffleNotice = useCallback(async (data: ShuffleNoticeData): Promise<ShuffleHandleResult | null> => {
    console.log(SHUFFLE_NOTICE, data);
    const { tableId, shuffleState } = data;

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.warn('[Shuffle] No player keys available');
      return null;
    }
    console.log('[SHUFFLE_NOTICE] Current player:', pkHex, keys);
    if (shuffleState.current_player_pk !== pkHex) {
      console.log('[Shuffle] Not my turn, waiting...');
      return null;
    }

    if (shuffleLoadingRef.current) {
      console.log('[Shuffle] Already processing a shuffle');
      return null;
    }

    const deckEncrypted = shuffleState.deck_encrypted;
    const aggregatePk = shuffleState.aggregate_pk;

    if (!deckEncrypted || deckEncrypted.length === 0) {
      console.warn('[Shuffle] No deck_encrypted in shuffle state');
      return null;
    }
    if (!aggregatePk) {
      console.warn('[Shuffle] No aggregate_pk');
      return null;
    }

    shuffleLoadingRef.current = true;
    setShuffleLoading(true);

    try {
      const deckJson = JSON.stringify(deckEncrypted);
      const shuffleResult = wrapCryptoOp(() => {
        const result = keys.shuffle(deckJson, aggregatePk);
        if (!result) throw new Error('Shuffle returned null');
        return typeof result === 'string' ? JSON.parse(result) : result;
      }, 'shuffle') as ShuffleResult;

      if (!shuffleResult.output_cards || !Array.isArray(shuffleResult.output_cards)) {
        throw new Error('Invalid shuffle result: missing output_cards');
      }

      const gameId = String(tableId);
      console.log(SHUFFLE_SUBMIT, { gameId, pkHex, cardCount: shuffleResult.output_cards.length });

      return {
        tableId,
        gameId,
        pkHex,
        shuffleResult,
      };
    } catch (e) {
      const err = e as Error;
      console.error('[Shuffle] Failed:', e);
      addMessage(`Shuffle failed: ${err.message || e}`);
      return null;
    } finally {
      shuffleLoadingRef.current = false;
      setShuffleLoading(false);
    }
  }, [playerKeys, pkHex, getPlayerKeys, addMessage]);

  const handleRevealNotice = useCallback(async (data: RevealNoticeData): Promise<void> => {
    console.log(REVEAL_NOTICE, data);
    const { table_id, phase, pending_players, player_assignments } = data;

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.warn('[Reveal] No player keys available');
      return;
    }

    if (!pending_players || !pending_players.includes(pkHex!)) {
      console.log('[Reveal] Not my turn for reveal');
      return;
    }

    if (revealLoadingRef.current) {
      console.log('[Reveal] Already processing reveal tokens');
      return;
    }

    const assignments = player_assignments || currentTableRef.current?.revealTokenState?.player_assignments;
    if (!assignments) {
      console.warn('[Reveal] No player assignments available');
      return;
    }

    const myAssignment = assignments[pkHex!];
    if (!myAssignment) {
      console.warn('[Reveal] No assignment found for my pk');
      return;
    }

    let cardsForPhase: unknown[] = [];
    const handCards = myAssignment.hand_cards || myAssignment.hand_card;
    if (handCards) {
      cardsForPhase = handCards.map((c: { encrypted_card?: string } | string) =>
        typeof c === 'string' ? c : c.encrypted_card || c
      );
    }
    const communityCards = myAssignment.community_cards || myAssignment.community_card;
    if (communityCards && communityCards.length > 0) {
      for (const cc of communityCards) {
        cardsForPhase.push(typeof cc === 'string' ? cc : cc.encrypted_card || cc);
      }
    }

    if (cardsForPhase.length === 0) {
      console.warn('[Reveal] No cards assigned');
      return;
    }

    revealLoadingRef.current = true;
    setRevealLoading(true);

    try {
      const cardJson = JSON.stringify(cardsForPhase);
      const tokens = wrapCryptoOp(() => {
        const tokensRaw = keys.batch_generate_reveal_token(cardJson);
        if (!tokensRaw) throw new Error('batch_generate_reveal_token returned null');
        let parsed: unknown[];
        if (typeof tokensRaw === 'string') {
          parsed = JSON.parse(tokensRaw);
        } else {
          parsed = tokensRaw;
        }
        if (!Array.isArray(parsed) || parsed.length === 0) {
          throw new Error('Invalid or empty tokens returned');
        }
        return parsed;
      }, 'batchGenerateRevealToken');

      socket?.emit(REVEAL_SUBMIT, {
        tableId: Number(table_id),
        pkHex: pkHex!,
        revealTokens: tokens as SubmitRevealToken[],
      });
      console.log('[Reveal] Submitted tokens:', { gameId: table_id, pkHex, tokens });

      addMessage(`Reveal ${phase}: ${tokens.length} tokens submitted`);
    } catch (e) {
      const err = e as Error;
      console.error('[Reveal] Failed:', e);
      addMessage(`Reveal token failed: ${err.message || e}`);
    } finally {
      revealLoadingRef.current = false;
      setRevealLoading(false);
    }
  }, [socket, playerKeys, pkHex, getPlayerKeys, addMessage]);

  const handleHandRevealResult = useCallback((data: HandRevealResultData): HandRevealReturn | null => {
    console.log(HAND_REVEAL_RESULT, data);
    const { tableId, playerPk, readableCards, deckPlaintext } = data;

    if (!readableCards || !Array.isArray(readableCards) || readableCards.length === 0) {
      console.warn('[HandReveal] No readable cards in payload');
      return null;
    }

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.warn('[HandReveal] No player keys available for decryption');
      return null;
    }

    const currentPkHex = pkHex || localStorage.getItem('pk');
    if (playerPk !== currentPkHex) {
      console.warn('[HandReveal] playerPk mismatch, ignoring:', { playerPk, currentPkHex });
      return null;
    }
    const decFailedCards: unknown[] = [];
    const decrypted: string[] = [];
    for (let i = 0; i < readableCards.length; i++) {
      const card = readableCards[i];
      const ctJson = JSON.stringify(card);
      const deckPlaintextJson = JSON.stringify(deckPlaintext);
      try {
        const result = wrapCryptoOp(() => {
          console.log('[HandReveal] Decrypting card:', ctJson);
          const decryptedStr = keys.decrypt_readable_card(ctJson, deckPlaintextJson);
          if (!decryptedStr) throw new Error('decrypt_readable_card returned null');
          return decryptedStr;
        }, 'decrypt_readable_card');
        console.log('[HandReveal] Decrypted card:', result);
        decrypted.push(result);
      } catch (e) {
        decFailedCards.push(card);
        const err = e as Error;
        console.error('[HandReveal] Decryption failed:', e);
        addMessage(`Hand reveal decryption failed: ${err.message || e}`);
        continue;
      }
    }
    if (decFailedCards.length > 0) {
      addMessage(`Hand reveal decryption failed for ${decFailedCards.length} cards`);
      return { failedCards: decFailedCards, playerPk: currentPkHex };
    } else {
      setDecryptedHandCards(decrypted);
      addMessage(`Hand revealed: ${decrypted.length} cards decrypted`);
      return null;
    }
  }, [playerKeys, getPlayerKeys, pkHex, addMessage]);

  const handleCommunityRevealResult = useCallback((data: CommunityRevealResultData): void => {
    console.log(COMMUNITY_REVEAL_RESULT, data);
    const { tableId, communityCards: cards } = data;

    if (!cards || !Array.isArray(cards) || cards.length === 0) {
      console.warn('[CommunityReveal] No community cards in payload');
      return;
    }

    setCommunityCards(cards);
    addMessage(`Community cards revealed: ${cards.length} cards`);
  }, [addMessage]);

  const handleReconstructNotice = useCallback(async (data: ReconstructNoticeData): Promise<ReconstructSubmitPayload | void> => {
    console.log(RECONSTRUCT_NOTICE, data);
    const { table_id, completed_players, pending_players, cards, coefficient_hex, player_readable_cards } = data;
    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.warn('[Reconstruct] No player keys available for decryption');
      return;
    }

    if (!pending_players || !pending_players.includes(pkHex!)) {
      console.log('[Reconstruct] Not my turn for reconstruct');
      return;
    }

    const myReadableCards = player_readable_cards?.[pkHex!];
    if (!myReadableCards || !myReadableCards.readable_cards || myReadableCards.readable_cards.length === 0) {
      console.warn('[Reconstruct] No readable cards assigned for my pk');
      return;
    }

    try {
      const originCardsJson = JSON.stringify(cards);
      const userReadableCardsJson = JSON.stringify(myReadableCards.readable_cards);

      const result = wrapCryptoOp(() => {
        const resultRaw = keys.reconstruct(originCardsJson, userReadableCardsJson, coefficient_hex);
        if (!resultRaw) throw new Error('reconstruct returned null');
        let parsed: ReconstructResult;
        if (typeof resultRaw === 'string') {
          parsed = JSON.parse(resultRaw);
        } else {
          parsed = resultRaw;
        }
        return parsed;
      }, 'reconstruct');

      console.log('RECONSTRUCT_NOTICE shuffle proof', result);
      console.log('[Reconstruct] Result:', result);
      addMessage(`Reconstruct submitted`);
      return {
        table_id,
        pk_hex: pkHex,
        output_cards: result.output_cards,
        swap_cards: result.swap_cards,
        proof: result.proof,
      } as ReconstructSubmitPayload;
    } catch (e) {
      const err = e as Error;
      console.error('[Reconstruct] Failed:', e);
      addMessage(`Reconstruct failed: ${err.message || e}`);
    }
  }, [playerKeys, pkHex, getPlayerKeys, addMessage]);

  return {
    handleShuffleNotice,
    handleRevealNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    handleReconstructNotice,
  };
};
