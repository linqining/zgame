import React, { useState, useEffect, useContext, useRef, useCallback } from 'react';
import authContext from '../auth/authContext';
import SocketContext from './socketContext';
import { Socket, io } from 'socket.io-client';
import {
  DISCONNECT,
  FETCH_LOBBY_INFO,
  PLAYERS_UPDATED,
  RECEIVE_LOBBY_INFO,
  TABLES_UPDATED,
} from '../../pokergame/actions';
import globalContext from '../global/globalContext';
import config from '../../clientConfig';
import { getToken } from '../../helpers/getToken';

interface ReceiveLobbyInfoPayload {
  tables: unknown[];
  players: unknown[];
  socketId: string;
}

const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isLoggedIn, walletAddress } = useContext(authContext) as { isLoggedIn: boolean; walletAddress: string | null };
  const { setTables, setPlayers } = useContext(globalContext) as {
    setTables: (tables: unknown[] | null) => void;
    setPlayers: (players: unknown[] | null) => void;
  };

  const [socket, setSocket] = useState<Socket | null>(null);
  const [socketId, setSocketId] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef<Socket | null>(null);

  const cleanUp = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.emit(DISCONNECT);
      socketRef.current.off();
      socketRef.current.io.off();
      socketRef.current.close();
      socketRef.current = null;
    }
    window.socket = undefined;
    setSocket(null);
    setSocketId(null);
    setIsConnected(false);
    setPlayers(null);
    setTables(null);
  }, [setPlayers, setTables]);

  useEffect(() => {
    window.addEventListener('beforeunload', cleanUp);
    return () => {
      window.removeEventListener('beforeunload', cleanUp);
      cleanUp();
    };
  }, [cleanUp]);

  useEffect(() => {
    const isAuthenticated = isLoggedIn || !!walletAddress;
    console.log('[WebSocketProvider] isAuthenticated:', isAuthenticated, 'isLoggedIn:', isLoggedIn, 'walletAddress:', walletAddress);

    if (isAuthenticated) {
      if (!socketRef.current) {
        console.log('[WebSocketProvider] Creating new socket to:', config.socketURI);
        const newSocket = io(config.socketURI, {
          transports: ['websocket'],
          upgrade: false,
          reconnection: true,
          reconnectionAttempts: 10,
          reconnectionDelay: 1000,
          reconnectionDelayMax: 5000,
        });

        newSocket.on(RECEIVE_LOBBY_INFO, ({ tables, players, socketId }: ReceiveLobbyInfoPayload) => {
          console.log(RECEIVE_LOBBY_INFO, tables, players, socketId);
          setSocketId(socketId);
          setTables(tables);
          setPlayers(players);
        });

        newSocket.on(PLAYERS_UPDATED, (players: unknown[]) => {
          console.log(PLAYERS_UPDATED, players);
          setPlayers(players);
        });

        newSocket.on(TABLES_UPDATED, (tables: unknown[]) => {
          console.log(TABLES_UPDATED, tables);
          setTables(tables);
        });

        // On reconnect, re-emit FETCH_LOBBY_INFO to trigger server-side reconnection logic
        // Note: FETCH_LOBBY_INFO is now emitted in the 'connect' handler above,
        // which covers both initial connect and reconnects.
        newSocket.io.on('reconnect', () => {
          console.log('[Socket] Reconnected');
        });

        newSocket.on('connect', () => {
          console.log('[Socket] Connected');
          setIsConnected(true);
          // Emit FETCH_LOBBY_INFO on every successful connection (initial + reconnects)
          const token = getToken();
          console.log('[Socket] connect event, token exists:', !!token);
          if (token) {
            console.log('[Socket] Emitting FETCH_LOBBY_INFO on connect');
            newSocket.emit(FETCH_LOBBY_INFO, token);
          } else {
            console.warn('[Socket] No token found in localStorage, cannot emit FETCH_LOBBY_INFO');
          }
        });

        newSocket.on('connect_error', (err) => {
          console.error('[Socket] Connect error:', err.message);
        });

        newSocket.on('disconnect', (reason) => {
          console.log('[Socket] Disconnected:', reason);
          setIsConnected(false);
        });

        socketRef.current = newSocket;
        window.socket = newSocket;
        setSocket(newSocket);
        // Note: FETCH_LOBBY_INFO is emitted in the 'connect' handler above,
        // ensuring it's only sent after the connection is fully established.
      } else {
        // Socket already exists, just re-emit FETCH_LOBBY_INFO if we have a token
        const token = getToken();
        if (token) socketRef.current.emit(FETCH_LOBBY_INFO, token);
      }
    } else {
      cleanUp();
    }
    // No cleanup here — we only clean up when isAuthenticated becomes false
    // or on unmount (handled by the other useEffect)
  }, [isLoggedIn, walletAddress]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <SocketContext.Provider value={{ socket, socketId, isConnected, cleanUp }}>
      {children}
    </SocketContext.Provider>
  );
};

export default WebSocketProvider;
