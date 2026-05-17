import React, { createContext, useState, useCallback, useEffect, useRef } from 'react';

const PlayerContext = createContext();

let wasmInitialized = false;
let wasmInitPromise = null;
let WasmClientPlayerClass = null;

async function ensureWasmReady() {
  if (wasmInitialized && WasmClientPlayerClass) return;

  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      if (typeof window.wasm_bindgen !== 'function') {
        throw new Error('wasm_bindgen not found. Make sure client_wasm.js is loaded.');
      }

      const exports = await window.wasm_bindgen('/wasm/client_wasm_bg.wasm');
      WasmClientPlayerClass = exports.WasmClientPlayer;

      if (!WasmClientPlayerClass) {
        throw new Error('WasmClientPlayer not found in WASM exports');
      }

      wasmInitialized = true;
    })();
  }

  await wasmInitPromise;
}

function parsePkProof(proofVal) {
  if (typeof proofVal === 'string') {
    return JSON.parse(proofVal);
  }
  return proofVal;
}

const PlayerProvider = ({ children }) => {
  const [playerKeys, setPlayerKeysState] = useState(null);
  const [pkProof, setPkProof] = useState(null);
  const [pkHex, setPkHex] = useState(null);
  const [skHex, setSkHex] = useState(null);
  const [gameId, setGameId] = useState(null);
  const [playerName, setPlayerName] = useState(null);
  const [wasmReady, setWasmReady] = useState(false);
  const keysRef = useRef(null);

  useEffect(() => {
    ensureWasmReady().then(() => setWasmReady(true)).catch((e) => {
      console.error('[PlayerContext] Failed to initialize WASM:', e);
    });
  }, []);

  const setPlayerKeys = useCallback((keys, proof, gid, name) => {
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

    localStorage.setItem(`sk_${gid}`, sk);
    localStorage.setItem(`pk_${gid}`, pk);
    localStorage.setItem(`player_${gid}`, name);
    localStorage.setItem('last_game_id', gid);
  }, []);

  const clearPlayerKeys = useCallback(() => {
    if (gameId) {
      localStorage.removeItem(`sk_${gameId}`);
      localStorage.removeItem(`pk_${gameId}`);
      localStorage.removeItem(`player_${gameId}`);
      localStorage.removeItem('last_game_id');
    }

    keysRef.current = null;
    setPlayerKeysState(null);
    setPkProof(null);
    setPkHex(null);
    setSkHex(null);
    setGameId(null);
    setPlayerName(null);

    console.log('[PlayerContext] Cleared all player data');
  }, [gameId]);

  const getPlayerKeys = useCallback((targetGameId) => {
    const gid = targetGameId || gameId;

    if (!gid) {
      console.warn('[PlayerContext] No game ID provided or stored');
      return null;
    }

    if (keysRef.current && gameId === gid) {
      return keysRef.current;
    }

    const storedSk = localStorage.getItem(`sk_${gid}`);
    if (!storedSk) {
      console.warn(`[PlayerContext] No SK found for game ${gid}`);
      return null;
    }

    try {
      console.log('[PlayerContext] Reconstructing player keys from SK...');
      const reconstructedKeys = WasmClientPlayerClass.from_sk(storedSk);
      keysRef.current = reconstructedKeys;
      console.log('[PlayerContext] Successfully reconstructed player keys');
      return reconstructedKeys;
    } catch (e) {
      console.error('[PlayerContext] Failed to reconstruct player keys:', e);
      return null;
    }
  }, [gameId]);

  const restoreSession = useCallback(() => {
    const savedGameId = localStorage.getItem('last_game_id');
    if (!savedGameId) return false;

    const savedSk = localStorage.getItem(`sk_${savedGameId}`);
    const savedPk = localStorage.getItem(`pk_${savedGameId}`);
    const savedName = localStorage.getItem(`player_${savedGameId}`);

    if (!savedSk || !savedPk || !savedName) {
      localStorage.removeItem('last_game_id');
      return false;
    }

    if (keysRef.current) return true;

    try {
      console.log('[PlayerContext] Restoring player session from storage...');
      const restoredKeys = WasmClientPlayerClass.from_sk(savedSk);
      const restoredProof = parsePkProof(restoredKeys.generate_pk_proof());

      setPlayerKeys(restoredKeys, restoredProof, savedGameId, savedName);
      console.log('[PlayerContext] Player session restored successfully!');
      return true;
    } catch (e) {
      console.error('[PlayerContext] Failed to restore player session:', e);
      localStorage.removeItem('last_game_id');
      return false;
    }
  }, [setPlayerKeys]);

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

export { PlayerContext, ensureWasmReady, parsePkProof };
export default PlayerProvider;
