import React, { useContext, useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import authContext from '../auth/authContext';
import socketContext from '../websocket/socketContext';
import { PlayerContext } from '../player/PlayerContext';
import GameContext from './gameContext';
import {
  Table,
  Card,
  GameMessage,
  Seat,
  CryptoEvent,
} from '../../types/game';
import { useCryptoOperations } from './useCryptoOperations';
import { useGameActions } from './useGameActions';
import { useGameSocket } from './useGameSocket';

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
  const [kickNotification, setKickNotification] = useState<string | null>(null);
  // ZK 密码学事件流（保留最近 100 条），供主牌桌可视化面板消费
  const [cryptoEvents, setCryptoEvents] = useState<CryptoEvent[]>([]);

  const currentTableRef = useRef<Table | null>(null);
  const shuffleLoadingRef = useRef(false);
  const revealLoadingRef = useRef(false);
  const isUnmountingRef = useRef(false);

  // Mark component as unmounting so the socket effect cleanup knows to leave table
  useEffect(() => {
    return () => {
      isUnmountingRef.current = true;
    };
  }, []);

  const isPlayerSeated = !!(currentTable && pkHex && currentTable.seats && Object.values(currentTable.seats).some(
    (seat: Seat) => seat && seat.player && seat.player.pkHex === pkHex
  ));

  const seatId: number | null = currentTable && pkHex && currentTable.seats
    ? Object.values(currentTable.seats).find(
        (seat: Seat) => seat && seat.player && seat.player.pkHex === pkHex
      )?.id ?? null
    : null;

  const displayTable = useMemo(() => {
    if (!currentTable || decryptedHandCards.length === 0 || seatId === null) {
      console.log('[displayTable] Skipping hand injection:', {
        hasTable: !!currentTable,
        decryptedCount: decryptedHandCards.length,
        seatId,
      });
      return currentTable;
    }
    const seat = currentTable.seats[seatId];
    if (!seat) {
      console.log('[displayTable] Seat not found for seatId:', seatId, 'available keys:', Object.keys(currentTable.seats));
      return currentTable;
    }
    const handCards: Card[] = decryptedHandCards.map((cardStr) => ({
      suit: cardStr.slice(0, 1),
      rank: cardStr.slice(1),
    }));
    console.log('[displayTable] Injecting decrypted hand cards:', handCards, 'for seatId:', seatId);
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

  const addMessage = useCallback((message: string) => {
    setMessages((prevMessages) => [...prevMessages, { text: message, timestamp: Date.now() }]);
    console.log(message);
  }, []);

  const clearKickNotification = useCallback(() => {
    setKickNotification(null);
  }, []);

  const {
    handleShuffleNotice,
    handleRevealNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    handleReconstructNotice,
  } = useCryptoOperations({
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
  });

  const gameActions = useGameActions({
    socket,
    navigate,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    seatId,
    isPlayerSeated,
  });

  useEffect(() => {
    if (turn && !turnTimeOutHandle) {
      const handle = setTimeout(gameActions.fold, 15000);
      setHandle(handle);
    } else {
      turnTimeOutHandle && clearTimeout(turnTimeOutHandle);
      turnTimeOutHandle && setHandle(null);
    }
  }, [turn]); // eslint-disable-line react-hooks/exhaustive-deps

  useGameSocket({
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
    leaveTable: gameActions.leaveTable,
    handleShuffleNotice,
    handleRevealNotice,
    handleReconstructNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
  });

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
        kickNotification,
        cryptoEvents,
        joinTable: gameActions.joinTable,
        leaveTable: gameActions.leaveTable,
        sitDown: gameActions.sitDown,
        standUp: gameActions.standUp,
        addMessage,
        fold: gameActions.fold,
        check: gameActions.check,
        call: gameActions.call,
        raise: gameActions.raise,
        rebuy: gameActions.rebuy,
        sittingOut: gameActions.sittingOut,
        sittingIn: gameActions.sittingIn,
        expelInitiate: gameActions.expelInitiate,
        clearKickNotification,
      }}
    >
      {children}
    </GameContext.Provider>
  );
};

export default GameState;
