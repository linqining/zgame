import React, { useContext, useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { withRouter } from 'react-router-dom';
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
  REVEAL_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
  EXPEL_INITIATE,
  EXPEL_VOTE,
  EXPEL_FORCE,
  EXPEL_RESULT,
} from '../../pokergame/actions';
import authContext from '../auth/authContext';
import socketContext from '../websocket/socketContext';
import { PlayerContext } from '../player/PlayerContext';
import { gameApi } from '../../helpers/api';
import GameContext from './gameContext';

function wrapCryptoOp(op, name) {
  try {
    return op();
  } catch (e) {
    console.error(`[Crypto] ${name} failed:`, e);
    throw e;
  }
}

const GameState = ({ history, children }) => {
  const { socket, socketId } = useContext(socketContext);
  const { loadUser } = useContext(authContext);
  const { playerKeys, pkHex, playerName, getPlayerKeys } = useContext(PlayerContext);

  const [messages, setMessages] = useState([]);
  const [currentTable, setCurrentTable] = useState(null);
  const [turn, setTurn] = useState(false);
  const [turnTimeOutHandle, setHandle] = useState(null);
  const [shuffleLoading, setShuffleLoading] = useState(false);
  const [revealLoading, setRevealLoading] = useState(false);
  const [decryptedHandCards, setDecryptedHandCards] = useState([]);
  const [communityCards, setCommunityCards] = useState([]);

  const currentTableRef = React.useRef(currentTable);
  const shuffleLoadingRef = useRef(false);
  const revealLoadingRef = useRef(false);

  const isPlayerSeated = !!(currentTable && socketId && currentTable.seats && Object.values(currentTable.seats).some(
    (seat) => seat && seat.player && seat.player.socketId === socketId
  ));

  const seatId = currentTable && socketId && currentTable.seats
    ? Object.values(currentTable.seats).find(
        (seat) => seat && seat.player && seat.player.socketId === socketId
      )?.id ?? null
    : null;

  const displayTable = useMemo(() => {
    if (!currentTable || decryptedHandCards.length === 0 || seatId === null) {
      return currentTable;
    }
    const seat = currentTable.seats[seatId];
    if (!seat) return currentTable;
    const handCards = decryptedHandCards.map((cardStr) => ({
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

  const addMessage = useCallback((message) => {
    setMessages((prevMessages) => [...prevMessages, message]);
    console.log(message);
  }, []);

  const handleShuffleNotice = useCallback(async (data) => {
    console.log(SHUFFLE_NOTICE, data);
    const { tableId, shuffle_state } = data;
    if (!shuffle_state?.is_active) return;

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.warn('[Shuffle] No player keys available');
      return;
    }

    if (shuffle_state.current_player_pk !== pkHex) {
      console.log('[Shuffle] Not my turn, waiting...');
      return;
    }

    if (shuffleLoadingRef.current) {
      console.log('[Shuffle] Already processing a shuffle');
      return;
    }

    const deckEncrypted = shuffle_state.deck_encrypted;
    const aggregatePk = shuffle_state.aggregate_pk;

    if (!deckEncrypted || deckEncrypted.length === 0) {
      console.warn('[Shuffle] No deck_encrypted in shuffle state');
      return;
    }
    if (!aggregatePk) {
      console.warn('[Shuffle] No aggregate_pk');
      return;
    }

    shuffleLoadingRef.current = true;
    setShuffleLoading(true);

    try {
      const deckJson = JSON.stringify(deckEncrypted);
      const shuffleResult = wrapCryptoOp(() => {
        const result = keys.shuffle(deckJson, aggregatePk);
        if (!result) throw new Error('Shuffle returned null');
        return typeof result === 'string' ? JSON.parse(result) : result;
      }, 'shuffle');

      if (!shuffleResult.output_cards || !Array.isArray(shuffleResult.output_cards)) {
        throw new Error('Invalid shuffle result: missing output_cards');
      }

      const gameId = String(tableId);
      await gameApi.shuffle(gameId, {
        pk_hex: pkHex,
        shuffle_data: {
          output_cards: shuffleResult.output_cards,
          proof: shuffleResult.proof,
        },
      });

      addMessage(`Shuffle submitted (${shuffleResult.output_cards.length} cards)`);
    } catch (e) {
      console.error('[Shuffle] Failed:', e);
      addMessage(`Shuffle failed: ${e.message || e}`);
    } finally {
      shuffleLoadingRef.current = false;
      setShuffleLoading(false);
    }
  }, [playerKeys, pkHex, getPlayerKeys, addMessage]);

  const handleRevealNotice = useCallback(async (data) => {
    console.log(REVEAL_NOTICE, data);
    const { table_id, phase, pending_players, player_assignments } = data;

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.warn('[Reveal] No player keys available');
      return;
    }

    if (!pending_players || !pending_players.includes(pkHex)) {
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

    const myAssignment = assignments[pkHex];
    if (!myAssignment) {
      console.warn('[Reveal] No assignment found for my pk');
      return;
    }

    let cardsForPhase = [];
    const handCards = myAssignment.hand_cards || myAssignment.hand_card;
    if (handCards) {
      cardsForPhase = handCards.map((c) => c.encrypted_card || c);
    }
    const communityCards = myAssignment.community_cards || myAssignment.community_card;
    if (communityCards && communityCards.length > 0) {
      for (const cc of communityCards) {
        cardsForPhase.push(cc.encrypted_card || cc);
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
        let parsed;
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

      addMessage(`Reveal ${phase}: ${tokens.length} tokens submitted`);
    } catch (e) {
      console.error('[Reveal] Failed:', e);
      addMessage(`Reveal token failed: ${e.message || e}`);
    } finally {
      revealLoadingRef.current = false;
      setRevealLoading(false);
    }
  }, [playerKeys, pkHex, getPlayerKeys, addMessage]);

  const handleHandRevealResult = useCallback(async (data) => {
    console.log(HAND_REVEAL_RESULT, data);
    const { tableId, playerPk, readableCards } = data;

    if (!readableCards || !Array.isArray(readableCards) || readableCards.length === 0) {
      console.warn('[HandReveal] No readable cards in payload');
      return;
    }

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      console.warn('[HandReveal] No player keys available for decryption');
      return;
    }

    const currentPkHex = pkHex || localStorage.getItem('pk');
    if (playerPk !== currentPkHex) {
      console.warn('[HandReveal] playerPk mismatch, ignoring:', { playerPk, currentPkHex });
      return;
    }

    try {
      const decrypted = [];
      for (const card of readableCards) {
        const ctJson = JSON.stringify(card);
        const result = wrapCryptoOp(() => {
          console.log('[HandReveal] Decrypting card:', ctJson);
          const decryptedStr = keys.decrypt_readable_card(ctJson);
          if (!decryptedStr) throw new Error('decrypt_readable_card returned null');
          return decryptedStr;
        }, 'decrypt_readable_card');
        console.log('[HandReveal] Decrypted card:', result);
        decrypted.push(result);
      }

      setDecryptedHandCards(decrypted);
      addMessage(`Hand revealed: ${decrypted.length} cards decrypted`);
    } catch (e) {
      console.error('[HandReveal] Decryption failed:', e);
      addMessage(`Hand reveal decryption failed: ${e.message || e}`);
    }
  }, [playerKeys, getPlayerKeys, pkHex, addMessage]);

  const handleCommunityRevealResult = useCallback((data) => {
    console.log(COMMUNITY_REVEAL_RESULT, data);
    const { tableId, communityCards: cards } = data;

    if (!cards || !Array.isArray(cards)) {
      console.warn('[CommunityReveal] No community cards in payload');
      return;
    }

    setCommunityCards(cards);
    addMessage(`Community cards revealed: ${cards.length} cards`);
  }, [addMessage]);

  useEffect(() => {
    if (socket) {
      window.addEventListener('unload', leaveTable);
      window.addEventListener('close', leaveTable);

      socket.on(TABLE_UPDATED, ({ table, message, from }) => {
        console.log(TABLE_UPDATED, table, message, from);
        setCurrentTable(table);
        message && addMessage(message);
      });

      socket.on(TABLE_JOINED, ({ table, message, from }) => {
        console.log(TABLE_JOINED, table, message, from);
        setCurrentTable(table);
      });

      socket.on(TABLE_LEFT, ({ tables, tableId }) => {
        console.log(TABLE_LEFT, tables, tableId);
        setCurrentTable(null);
        loadUser(localStorage.token);
        setMessages([]);
        setDecryptedHandCards([]);
        setCommunityCards([]);
      });

      socket.on(SHUFFLE_NOTICE, (data) => {
        handleShuffleNotice(data);
      });

      socket.on(REVEAL_NOTICE, (data) => {
        handleRevealNotice(data);
      });

      socket.on(EXPEL_RESULT, (data) => {
        console.log(EXPEL_RESULT, data);
        if (data?.expelled) {
          addMessage('Player expelled by vote');
        } else {
          addMessage('Expel vote timed out');
        }
      });

      socket.on(HAND_REVEAL_RESULT, (data) => {
        handleHandRevealResult(data);
      });

      socket.on(COMMUNITY_REVEAL_RESULT, (data) => {
        handleCommunityRevealResult(data);
      });
    }
    return () => leaveTable();
  }, [socket, handleShuffleNotice, handleRevealNotice, handleHandRevealResult, handleCommunityRevealResult]); // eslint-disable-line react-hooks/exhaustive-deps

  const joinTable = (tableId) => {
    console.log(JOIN_TABLE, tableId);
    socket.emit(JOIN_TABLE, tableId);
  };

  const leaveTable = () => {
    isPlayerSeated && standUp();
    currentTableRef &&
      currentTableRef.current &&
      currentTableRef.current.id &&
      socket.emit(LEAVE_TABLE, currentTableRef.current.id);
    history.push('/');
  };

  const sitDown_old = (tableId, seatId, amount) => {
    socket.emit(SIT_DOWN, { tableId, seatId, amount });
  }

  const sitDown = async (tableId, seatId, amount) => {
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

    const deckEncrypted = table.shuffleState?.deckEncrypted || table.deck?.cards;
    if (!deckEncrypted || deckEncrypted.length === 0) {
      console.error('[SitDown] No deck_encrypted available');
      addMessage('Cannot sit down: no encrypted deck');
      return;
    }
    try {
      const pkHexes = (Object.values(table.seats) || [])
        .filter((p) => p.player && p.player.pkHex && p.player.pkHex!==pkHex).map((p) => p.player.pkHex);
      const pkHexesJson = JSON.stringify(pkHexes);
      const aggPkHex = window.wasm_bindgen.compute_aggregate_key(pkHexesJson);

      const deckEncryptedJson = JSON.stringify(deckEncrypted);

      const joinResult = wrapCryptoOp(() => {
        const result = keys.join_game_and_shuffle(deckEncryptedJson, aggPkHex);
        if (!result) throw new Error('join_game_and_shuffle returned null');
        return typeof result === 'string' ? JSON.parse(result) : result;
      }, 'join_game_and_shuffle');

      const maskAndShuffleRound = {
        mask_cards: joinResult.mask_and_shuffle_round.mask_cards,
        output_cards: joinResult.mask_and_shuffle_round.output_cards,
        remask_proof: joinResult.mask_and_shuffle_round.remask_proof,
        shuffle_proof: joinResult.mask_and_shuffle_round.shuffle_proof,
      };
      const pkProof = joinResult.pk_ownership_proof;
      // const gameId = String(tableId);
      socket.emit(SIT_DOWN_V2, { tableId, seatId, amount,pkHex,pkProof,maskAndShuffleRound });
      addMessage('Joined table and shuffled successfully');
    } catch (e) {
      console.error('[SitDown] join_and_shuffle failed:', e);
      addMessage(`Sit down failed: ${e.message || e}`);
    }
  };

  const rebuy = (tableId, seatId, amount) => {
    socket.emit(REBUY, { tableId, seatId, amount });
  };

  const standUp = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket.emit(STAND_UP, currentTableRef.current.id);
  };

  const fold = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket.emit(FOLD, currentTableRef.current.id);
  };

  const check = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket.emit(CHECK, currentTableRef.current.id);
  };

  const call = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket.emit(CALL, currentTableRef.current.id);
  };

  const raise = (amount) => {
    currentTableRef &&
      currentTableRef.current &&
      socket.emit(RAISE, { tableId: currentTableRef.current.id, amount });
  };

  const sittingOut = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket.emit(SITTING_OUT, currentTableRef.current.id);
  };

  const sittingIn = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket.emit(SITTING_IN, currentTableRef.current.id);
  };

  const expelInitiate = (tableId, targetPlayerPk) => {
    socket.emit(EXPEL_INITIATE, { tableId, targetPlayerPk });
  };

  const expelVote = (tableId, vote) => {
    socket.emit(EXPEL_VOTE, { tableId, vote });
  };

  const expelForce = (tableId, targetPlayerPk) => {
    socket.emit(EXPEL_FORCE, { tableId, targetPlayerPk });
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
        expelVote,
        expelForce,
      }}
    >
      {children}
    </GameContext.Provider>
  );
};

export default withRouter(GameState);
