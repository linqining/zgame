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
  const socketRef = useRef<Socket | null>(null);

  const cleanUp = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.emit(DISCONNECT);
      socketRef.current.off();
      socketRef.current.close();
      socketRef.current = null;
    }
    window.socket = undefined;
    setSocket(null);
    setSocketId(null);
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

    if (isAuthenticated) {
      if (!socketRef.current) {
        const newSocket = io(config.socketURI, {
          transports: ['websocket'],
          upgrade: false,
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

        socketRef.current = newSocket;
        window.socket = newSocket;
        setSocket(newSocket);

        const token = localStorage.token;
        if (token) newSocket.emit(FETCH_LOBBY_INFO, token);
      } else {
        // Socket already exists, just re-emit FETCH_LOBBY_INFO if we have a token
        const token = localStorage.token;
        if (token) socketRef.current.emit(FETCH_LOBBY_INFO, token);
      }
    } else {
      cleanUp();
    }
    // No cleanup here — we only clean up when isAuthenticated becomes false
    // or on unmount (handled by the other useEffect)
  }, [isLoggedIn, walletAddress]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <SocketContext.Provider value={{ socket, socketId, cleanUp }}>
      {children}
    </SocketContext.Provider>
  );
};

export default WebSocketProvider;
