import React, { createContext, useContext, useState, useCallback } from 'react'
import { PKOwnershipProofJson } from '../../api/secretPokerClient'

// WasmClientPlayer type - will be loaded from WASM module at runtime
interface WasmClientPlayer {
  get_pk_hex(): string
  get_sk_hex(): string
  generate_pk_proof(): string
  join_game_and_shuffle(deckEncryptedJson: string, aggPkHex: string): string
  shuffle(shuffleRoundIndex: number | undefined, aggregatePk: string): any
  batch_generate_reveal_token(cardJson: string): any
  verify_remask_proof(deckJson: string, maskCardsJson: string, remaskProofJson: string, pkHex: string): boolean
}

// Factory function for creating WasmClientPlayer from stored secret key
// Will be implemented when WASM module is integrated
type WasmClientPlayerConstructor = {
  from_sk(skHex: string): WasmClientPlayer
}

interface PlayerKeysData {
  playerKeys: WasmClientPlayer | null
  pk_proof: PKOwnershipProofJson | null
  pk_hex: string | null
  sk_hex: string | null
  gameId: string | null
  playerName: string | null
}

interface PlayerContextType extends PlayerKeysData {
  setPlayerKeys: (keys: WasmClientPlayer, pkProof: PKOwnershipProofJson, gameId: string, playerName: string) => void
  clearPlayerKeys: () => void
  getPlayerKeys: (gameId?: string) => WasmClientPlayer | null
}

const PlayerContext = createContext<PlayerContextType | undefined>(undefined)

export function PlayerProvider({ children }: { children: React.ReactNode }) {
  const [playerData, setPlayerData] = useState<PlayerKeysData>({
    playerKeys: null,
    pk_proof: null,
    pk_hex: null,
    sk_hex: null,
    gameId: null,
    playerName: null,
  })

  const setPlayerKeys = useCallback((
    keys: WasmClientPlayer,
    pkProof: PKOwnershipProofJson,
    gameId: string,
    playerName: string
  ) => {
    const pkHex = keys.get_pk_hex()
    const skHex = keys.get_sk_hex()

    setPlayerData({
      playerKeys: keys,
      pk_proof: pkProof,
      pk_hex: pkHex,
      sk_hex: skHex,
      gameId: gameId,
      playerName: playerName,
    })

    localStorage.setItem(`sk_${gameId}`, skHex)
    localStorage.setItem(`pk_${gameId}`, pkHex)
    localStorage.setItem(`player_${gameId}`, playerName)
    localStorage.setItem('last_game_id', gameId)
  }, [])

  const clearPlayerKeys = useCallback(() => {
    if (playerData.gameId) {
      localStorage.removeItem(`sk_${playerData.gameId}`)
      localStorage.removeItem(`pk_${playerData.gameId}`)
      localStorage.removeItem(`player_${playerData.gameId}`)
      localStorage.removeItem('last_game_id')
    }

    setPlayerData({
      playerKeys: null,
      pk_proof: null,
      pk_hex: null,
      sk_hex: null,
      gameId: null,
      playerName: null,
    })
  }, [playerData.gameId])

  const getPlayerKeys = useCallback((gameId?: string): WasmClientPlayer | null => {
    const targetGameId = gameId || playerData.gameId

    if (!targetGameId) {
      return null
    }

    if (playerData.playerKeys && playerData.gameId === targetGameId) {
      return playerData.playerKeys
    }

    const storedSk = localStorage.getItem(`sk_${targetGameId}`)
    if (!storedSk) {
      return null
    }

    try {
      // Dynamic import of WASM module
      // This will be resolved at runtime when the WASM pkg is available
      return null // Placeholder - actual implementation requires WASM module
    } catch (e) {
      console.error('[PlayerContext] Failed to reconstruct player keys:', e)
      return null
    }
  }, [playerData.playerKeys, playerData.gameId])

  return (
    <PlayerContext.Provider value={{
      ...playerData,
      setPlayerKeys,
      clearPlayerKeys,
      getPlayerKeys,
    }}>
      {children}
    </PlayerContext.Provider>
  )
}

export function usePlayerContext() {
  const context = useContext(PlayerContext)
  if (context === undefined) {
    throw new Error('usePlayerContext must be used within a PlayerProvider')
  }
  return context
}

export default PlayerContext
