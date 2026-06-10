import React, { useContext, useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { compute_aggregate_key } from '@linqining/client-wasm';
import {
  CALL,
  CHECK,
  FOLD,
  JOIN_TABLE,
  LEAVE_TABLE,
  RAISE,
  REBUY,
  SIT_DOWN,
  SIT_DOWN_V2,
  STAND_UP,
  SITTING_OUT,
  SITTING_IN,
  TABLE_JOINED,
  TABLE_LEFT,
  TABLE_UPDATED,
  SHUFFLE_NOTICE,
  SHUFFLE_SUBMIT,
  RECONSTRUCT_INITIATE,
  RECONSTRUCT_NOTICE,
  RECONSTRUCT_SUBMIT,
  RECONSTRUCT_RESULT,
  REVEAL_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
  REDEAL_NOTICE,
  REDEAL_RESULT,
  REDEAL_REQUEST,
} from '../../pokergame/actions';
import authContext from '../auth/authContext';
import socketContext from '../websocket/socketContext';
import { PlayerContext } from '../player/PlayerContext';
import { gameApi } from '../../helpers/api';
import GameContext from './gameContext';
import {
  RoundState,
  Table,
  Card,
  GameContextType,
  GameMessage,
  ShuffleState,
  Seat,
} from '../../types/game';

interface ShuffleNoticeData {
  tableId: string;
  shuffleState: ShuffleState;
}

interface ShuffleResult {
  output_cards: string[][];
  shuffle_proof: string;
}

interface RevealNoticeData {
  table_id: string;
  phase: string;
  pending_players: string[];
  player_assignments?: Record<string, {
    hand_cards?: Array<{ encrypted_card: string } | string>;
    community_cards?: Array<{ encrypted_card: string } | string>;
    hand_card?: Array<{ encrypted_card: string } | string>;
    community_card?: Array<{ encrypted_card: string } | string>;
  }>;
}

interface HandRevealResultData {
  tableId: string;
  playerPk: string;
  readableCards: unknown[];
  deckPlaintext: unknown;
}

interface CommunityRevealResultData {
  tableId: string;
  communityCards: Card[];
}

interface ReconstructNoticeData {
  table_id: string;
  completed_players: string[];
  pending_players: string[];
  cards: unknown[];
  coefficient_hex: string;
  player_readable_cards?: Record<string, {
    readable_cards: unknown[];
  }>;
}

interface TableUpdatedPayload {
  table: Table;
  message?: string;
  from?: string;
}

interface TableJoinedPayload {
  table: Table;
  message?: string;
  from?: string;
}

interface TableLeftPayload {
  tables: unknown[];
  tableId: string;
}

interface ReconstructSubmitPayload {
  table_id: string;
  pk_hex: string;
  output_cards: string[][];
  swap_cards: string[][];
  proof: string;
}

interface HandRevealReturn {
  failedCards: unknown[];
  playerPk: string;
  failedCardIndices?: number[];
}

interface ReconstructResult {
  output_cards: string[][];
  swap_cards: string[][];
  proof: string;
}

interface JoinAndShuffleResult {
  mask_and_shuffle_round: {
    mask_cards: unknown;
    output_cards: unknown;
    remask_proof: unknown;
    shuffle_proof: unknown;
  };
  pk_ownership_proof: unknown;
}

function wrapCryptoOp<T>(op: () => T, name: string): T {
  try {
    return op();
  } catch (e) {
    console.error(`[Crypto] ${name} failed:`, e);
    throw e;
  }
}

const GameState: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const navigate = useNavigate();
  const { socket, socketId } = useContext(socketContext)!;
  const { loadUser } = useContext(authContext) as { loadUser: (token: string) => void };
  const { playerKeys, pkHex, playerName, getPlayerKeys } = useContext(PlayerContext)!;

  const [messages, setMessages] = useState<GameMessage[]>([]);
  const [currentTable, setCurrentTable] = useState<Table | null>(null);
  const [turn, setTurn] = useState(false);
  const [turnTimeOutHandle, setHandle] = useState<ReturnType<typeof setTimeout> | null>(null);
  const [shuffleLoading, setShuffleLoading] = useState(false);
  const [revealLoading, setRevealLoading] = useState(false);
  const [decryptedHandCards, setDecryptedHandCards] = useState<string[]>([]);
  const [communityCards, setCommunityCards] = useState<Card[]>([]);

  const currentTableRef = useRef<Table | null>(null);
  const shuffleLoadingRef = useRef(false);
  const revealLoadingRef = useRef(false);

  const isPlayerSeated = !!(currentTable && socketId && currentTable.seats && Object.values(currentTable.seats).some(
    (seat: Seat) => seat && seat.player && seat.player.socketId === socketId
  ));

  const seatId: number | null = currentTable && socketId && currentTable.seats
    ? Object.values(currentTable.seats).find(
        (seat: Seat) => seat && seat.player && seat.player.socketId === socketId
      )?.id ?? null
    : null;

  const displayTable = useMemo(() => {
    if (!currentTable || decryptedHandCards.length === 0 || seatId === null) {
      return currentTable;
    }
    const seat = currentTable.seats[seatId];
    if (!seat) return currentTable;
    const handCards: Card[] = decryptedHandCards.map((cardStr) => ({
      suit: cardStr.slice(0, 1),
      rank: cardStr.slice(1),
    }));
    return {
      ...currentTable,
      seats: {
        ...currentTable.seats,
        [seatId]: {
          ...seat,
          hand: handCards,
        },
      },
    };
  }, [currentTable, decryptedHandCards, seatId]);

  useEffect(() => {
    currentTableRef.current = currentTable;

    isPlayerSeated &&
      seatId && currentTable.seats &&
      currentTable.seats[seatId] &&
      turn !== currentTable.seats[seatId].turn &&
      setTurn(currentTable.seats[seatId].turn);
  }, [currentTable]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (turn && !turnTimeOutHandle) {
      const handle = setTimeout(fold, 15000);
      setHandle(handle);
    } else {
      turnTimeOutHandle && clearTimeout(turnTimeOutHandle);
      turnTimeOutHandle && setHandle(null);
    }
  }, [turn]); // eslint-disable-line react-hooks/exhaustive-deps

  const addMessage = useCallback((message: string) => {
    setMessages((prevMessages) => [...prevMessages, { text: message, timestamp: Date.now() }]);
    console.log(message);
  }, []);

  const handleShuffleNotice = useCallback(async (data: ShuffleNoticeData) => {
    console.log(SHUFFLE_NOTICE, data);
    const { tableId, shuffleState } = data;
    if (!shuffleState?.is_active) return null;

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

  const handleRevealNotice = useCallback(async (data: RevealNoticeData) => {
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

      const gameId = String(table_id);
      await gameApi.submitRevealToken(gameId, {
        pk_hex: pkHex,
        reveal_tokens: tokens,
      });
      console.log('[Reveal] Submitted tokens:', { gameId, pkHex, tokens });

      addMessage(`Reveal ${phase}: ${tokens.length} tokens submitted`);
    } catch (e) {
      const err = e as Error;
      console.error('[Reveal] Failed:', e);
      addMessage(`Reveal token failed: ${err.message || e}`);
    } finally {
      revealLoadingRef.current = false;
      setRevealLoading(false);
    }
  }, [playerKeys, pkHex, getPlayerKeys, addMessage]);

  const handleHandRevealResult = useCallback(async (data: HandRevealResultData) => {
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

  const handleCommunityRevealResult = useCallback((data: CommunityRevealResultData) => {
    console.log(COMMUNITY_REVEAL_RESULT, data);
    const { tableId, communityCards: cards } = data;

    if (!cards || !Array.isArray(cards)) {
      console.warn('[CommunityReveal] No community cards in payload');
      return;
    }

    setCommunityCards(cards);
    addMessage(`Community cards revealed: ${cards.length} cards`);
  }, [addMessage]);

  const handleReconstructNotice = useCallback(async (data: ReconstructNoticeData) => {
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

  useEffect(() => {
    const onUnload = () => leaveTable(false);
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

      socket.on(TABLE_LEFT, ({ tables, tableId }: TableLeftPayload) => {
        console.log(TABLE_LEFT, tables, tableId);
        setCurrentTable(null);
        loadUser(localStorage.token);
        setMessages([]);
        setDecryptedHandCards([]);
        setCommunityCards([]);
      });

      socket.on(SHUFFLE_NOTICE, async (data: ShuffleNoticeData) => {
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
        const redealInfo = handleHandRevealResult(data) as unknown as HandRevealReturn | null;
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
        const redealInfo = handleHandRevealResult(data) as unknown as HandRevealReturn | null;
        if (redealInfo) {
          addMessage(`Redeal decryption still failed for ${redealInfo.failedCardIndices?.length || 0} cards`);
        } else {
          addMessage('Redeal successful, new cards decrypted');
        }
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
      leaveTable();
    };
  }, [socket, handleShuffleNotice, handleRevealNotice, handleReconstructNotice, handleHandRevealResult, handleCommunityRevealResult]); // eslint-disable-line react-hooks/exhaustive-deps

  const joinTable = (tableId: number) => {
    console.log(JOIN_TABLE, tableId);
    socket?.emit(JOIN_TABLE, tableId);
  };

  const leaveTable = (shouldNavigate = true) => {
    isPlayerSeated && standUp();
    currentTableRef &&
      currentTableRef.current &&
      currentTableRef.current.id &&
      socket?.emit(LEAVE_TABLE, currentTableRef.current.id);
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
      const pkHexes = (Object.values(table.seats) || [])
        .filter((p: Seat) => p.player && p.player.pkHex && p.player.pkHex !== pkHex).map((p: Seat) => p.player!.pkHex);
      const pkHexesJson = JSON.stringify(pkHexes);
      const aggPkHex = compute_aggregate_key(pkHexesJson);

      const deckEncryptedJson = JSON.stringify(deckEncrypted);
      console.log('SIT_DOWN_V2', tableId, seatId, amount, pkHex, aggPkHex, deckEncryptedJson);
      const joinResult = wrapCryptoOp(() => {
        const result = keys.join_game_and_shuffle(deckEncryptedJson, aggPkHex);
        if (!result) throw new Error('join_game_and_shuffle returned null');
        return typeof result === 'string' ? JSON.parse(result) : result;
      }, 'join_game_and_shuffle') as JoinAndShuffleResult;

      const maskAndShuffleRound = {
        mask_cards: joinResult.mask_and_shuffle_round.mask_cards,
        output_cards: joinResult.mask_and_shuffle_round.output_cards,
        remask_proof: joinResult.mask_and_shuffle_round.remask_proof,
        shuffle_proof: joinResult.mask_and_shuffle_round.shuffle_proof,
      };
      const pkProof = joinResult.pk_ownership_proof;
      console.log('SIT_DOWN_V2', tableId, seatId, amount, pkHex, pkProof, maskAndShuffleRound, keys.get_pk_hex());
      socket?.emit(SIT_DOWN_V2, { tableId, seatId, amount, pkHex, pkProof, maskAndShuffleRound });
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

  const standUp = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(STAND_UP, currentTableRef.current.id);
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

  return (
    <GameContext.Provider
      value={{
        messages,
        currentTable: displayTable,
        isPlayerSeated,
        seatId,
        shuffleLoading,
        revealLoading,
        decryptedHandCards,
        communityCards,
        joinTable,
        leaveTable,
        sitDown,
        standUp,
        addMessage,
        fold,
        check,
        call,
        raise,
        rebuy,
        sittingOut,
        sittingIn,
        expelInitiate,
      }}
    >
      {children}
    </GameContext.Provider>
  );
};

export default GameState;
