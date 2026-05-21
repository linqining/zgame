import React, { createContext, useState, useCallback, useEffect, useRef } from 'react';
const PlayerContext = createContext();

let wasmInitialized = false;
let wasmInitPromise = null;
let wasmClientPlayer = null;

async function ensureWasmReady() {
  if (wasmInitialized && wasmClientPlayer) return;

  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      if (typeof window.wasm_bindgen !== 'function') {
        throw new Error('wasm_bindgen not found. Make sure client_wasm.js is loaded via <script>.');
      }

      await window.wasm_bindgen('/wasm/client_wasm_bg.wasm');
      wasmClientPlayer = window.wasm_bindgen.WasmClientPlayer;

      if (!wasmClientPlayer) {
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
  const restoreSessionRef = useRef(null);
  const getPlayerKeysRef = useRef(null);

  useEffect(() => {
    ensureWasmReady().then(() => {
      setWasmReady(true);
      if (restoreSessionRef.current) {
        const restored = restoreSessionRef.current();
        if (!restored && getPlayerKeysRef.current) {
          getPlayerKeysRef.current();
        }
      }
    }).catch((e) => {
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

  const getPlayerKeys = useCallback(() => {
    if (keysRef.current) {
      return keysRef.current;
    }

    const storedSk = localStorage.getItem('sk');
    if (!storedSk) {
      console.warn('[PlayerContext] No SK found in storage, generating new keys');
      const newKeys = new wasmClientPlayer();
      let sk = newKeys.get_sk_hex();
      let pk = newKeys.get_pk_hex();
      localStorage.setItem('sk', sk);
      localStorage.setItem('pk', pk);
      const restoredProof = parsePkProof(newKeys.generate_pk_proof());
      setPlayerKeys(newKeys, restoredProof, "", pk);
      return newKeys;
    }

    try {
      console.log('[PlayerContext] Reconstructing player keys from SK...');
      const reconstructedKeys = wasmClientPlayer.from_sk(storedSk);
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
  }, []);

  const restoreSession = useCallback(() => {
    const savedGameId = localStorage.getItem('last_game_id');
    const savedSk = localStorage.getItem('sk');
    const savedPk = localStorage.getItem('pk');
    const savedName = localStorage.getItem('player_name');

    if (!savedSk) {
      return false;
    }

    if (keysRef.current) return true;

    try {
      console.log('[PlayerContext] Restoring player session from storage...');
      const restoredKeys = wasmClientPlayer.from_sk(savedSk);
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

export { PlayerContext, ensureWasmReady, parsePkProof, wasmClientPlayer };
export default PlayerProvider;
