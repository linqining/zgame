import React, { createContext, useState, useCallback, useEffect, useRef } from 'react';
import { PlayerContextType, PkProofData } from '../../types/player';
import init, { WasmClientPlayer } from '@linqining/client-wasm';
import wasmUrl from '@linqining/client-wasm/client_wasm_bg.wasm?url';

const PlayerContext = createContext<PlayerContextType | undefined>(undefined);

let wasmInitialized = false;
let wasmInitPromise: Promise<void> | null = null;

export async function ensureWasmReady() {
  if (wasmInitialized) return;

  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      await init({ module_or_path: wasmUrl });
      wasmInitialized = true;
    })();
  }

  await wasmInitPromise;
}

function parsePkProof(proofVal: unknown): PkProofData {
  if (typeof proofVal === 'string') {
    return JSON.parse(proofVal);
  }
  return proofVal as PkProofData;
}

const PlayerProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [playerKeys, setPlayerKeysState] = useState<WasmClientPlayer | null>(null);
  const [pkProof, setPkProof] = useState<PkProofData | null>(null);
  const [pkHex, setPkHex] = useState<string | null>(null);
  const [skHex, setSkHex] = useState<string | null>(null);
  const [gameId, setGameId] = useState<string | null>(null);
  const [playerName, setPlayerName] = useState<string | null>(null);
  const [wasmReady, setWasmReady] = useState(false);
  const keysRef = useRef<WasmClientPlayer | null>(null);
  const restoreSessionRef = useRef<(() => boolean) | null>(null);
  const getPlayerKeysRef = useRef<(() => WasmClientPlayer | null) | null>(null);

  useEffect(() => {
    ensureWasmReady().then(() => {
      setWasmReady(true);
      if (restoreSessionRef.current) {
        const restored = restoreSessionRef.current();
        if (!restored && getPlayerKeysRef.current) {
          getPlayerKeysRef.current();
        }
      }
    }).catch((e: unknown) => {
      console.error('[PlayerContext] Failed to initialize WASM:', e);
    });
  }, []);

  const setPlayerKeys = useCallback((keys: WasmClientPlayer, proof: PkProofData, gid: string, name: string) => {
    const pk = keys.get_pk_hex();
    const sk = keys.get_sk_hex();

    console.log('[PlayerContext] Storing player keys');
    console.log('[PlayerContext]   - Game ID:', gid);
    console.log('[PlayerContext]   - Player name:', name);

    keysRef.current = keys;
    setPlayerKeysState(keys);
    setPkProof(parsePkProof(proof));
    setPkHex(pk);
    setSkHex(sk);
    setGameId(gid);
    setPlayerName(name);

    localStorage.setItem('sk', sk);
    localStorage.setItem('pk', pk);
    localStorage.setItem('player_name', name);
    localStorage.setItem('last_game_id', gid);
  }, []);

  const clearPlayerKeys = useCallback(() => {
    localStorage.removeItem('sk');
    localStorage.removeItem('pk');
    localStorage.removeItem('player_name');
    localStorage.removeItem('last_game_id');

    keysRef.current = null;
    setPlayerKeysState(null);
    setPkProof(null);
    setPkHex(null);
    setSkHex(null);
    setGameId(null);
    setPlayerName(null);

    console.log('[PlayerContext] Cleared all player data');
  }, []);

  const getPlayerKeys = useCallback((): WasmClientPlayer | null => {
    if (keysRef.current) {
      return keysRef.current;
    }

    if (!wasmInitialized) {
      console.error('[PlayerContext] WASM not initialized');
      return null;
    }

    const storedSk = localStorage.getItem('sk');
    if (!storedSk) {
      console.warn('[PlayerContext] No SK found in storage, generating new keys');
      const newKeys = new WasmClientPlayer();
      const sk = newKeys.get_sk_hex();
      const pk = newKeys.get_pk_hex();
      localStorage.setItem('sk', sk);
      localStorage.setItem('pk', pk);
      const restoredProof = parsePkProof(newKeys.generate_pk_proof());
      setPlayerKeys(newKeys, restoredProof, "", pk);
      return newKeys;
    }

    try {
      console.log('[PlayerContext] Reconstructing player keys from SK...', storedSk);
      const reconstructedKeys = WasmClientPlayer.from_sk(storedSk);
      const restoredProof = parsePkProof(reconstructedKeys.generate_pk_proof());
      const pk = reconstructedKeys.get_pk_hex();
      const savedName = localStorage.getItem('player_name') || '';
      const savedGameId = localStorage.getItem('last_game_id') || '';
      setPlayerKeys(reconstructedKeys, restoredProof, savedGameId, savedName);
      console.log('[PlayerContext] Successfully reconstructed player keys');
      return reconstructedKeys;
    } catch (e) {
      console.error('[PlayerContext] Failed to reconstruct player keys:', e);
      return null;
    }
  }, [setPlayerKeys]);

  const restoreSession = useCallback((): boolean => {
    const savedGameId = localStorage.getItem('last_game_id');
    const savedSk = localStorage.getItem('sk');
    const savedName = localStorage.getItem('player_name');

    if (!savedSk) {
      return false;
    }

    if (keysRef.current) return true;

    if (!wasmInitialized) {
      console.error('[PlayerContext] WASM not initialized');
      return false;
    }

    try {
      console.log('[PlayerContext] Restoring player session from storage...');
      const restoredKeys = WasmClientPlayer.from_sk(savedSk);
      const restoredProof = parsePkProof(restoredKeys.generate_pk_proof());

      setPlayerKeys(restoredKeys, restoredProof, savedGameId || '', savedName || '');
      console.log('[PlayerContext] Player session restored successfully!');
      return true;
    } catch (e) {
      console.error('[PlayerContext] Failed to restore player session:', e);
      localStorage.removeItem('last_game_id');
      return false;
    }
  }, [setPlayerKeys]);

  restoreSessionRef.current = restoreSession;
  getPlayerKeysRef.current = getPlayerKeys;

  useEffect(() => {
    console.log('[PlayerContext] Context updated:', {
      hasKeys: !!playerKeys,
      gameId,
      playerName,
      wasmReady,
    });
  }, [playerKeys, gameId, playerName, wasmReady]);

  return (
    <PlayerContext.Provider
      value={{
        playerKeys,
        pkProof,
        pkHex,
        skHex,
        gameId,
        playerName,
        wasmReady,
        setPlayerKeys,
        clearPlayerKeys,
        getPlayerKeys,
        restoreSession,
      }}
    >
      {children}
    </PlayerContext.Provider>
  );
};

export { PlayerContext };
export default PlayerProvider;
