import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, RefreshCw, AlertCircle } from 'lucide-react'
import api, { GameState } from '../api/secretPokerClient'
import { PlayerName } from '../components/game/PlayerName'
import { gameWsClient } from '../api/wsClient'

export default function GameTable() {
  const { gameId } = useParams<{ gameId: string }>()
  const navigate = useNavigate()
  const [game, setGame] = useState<GameState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [logs, setLogs] = useState<string[]>([])

  const addLog = useCallback((msg: string) => {
    setLogs(prev => [...prev.slice(-19), `[${new Date().toLocaleTimeString()}] ${msg}`])
  }, [])

  const fetchState = useCallback(async () => {
    if (!gameId) return
    try {
      const state = await api.getGame(gameId)
      setGame(state)
      setError(null)
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to fetch game state'
      setError(msg)
      addLog(`Error: ${msg}`)
    } finally {
      setLoading(false)
    }
  }, [gameId, addLog])

  useEffect(() => {
    if (!gameId) return
    addLog('Connecting to game...')
    fetchState()

    gameWsClient.connect(gameId, {
      onMessage: (data) => {
        setGame(data)
        addLog(`[WS] State update: ${data.phase ?? 'Unknown'}`)
      },
      onError: () => addLog('[WS] Connection error'),
      onClose: () => addLog('[WS] Disconnected, reconnecting...'),
    })

    return () => {
      gameWsClient.disconnect()
    }
  }, [gameId, fetchState, addLog])

  function formatPhase(phase: string) {
    return phase.replace(/([A-Z])/g, ' $1').trim()
  }

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '1rem',
        background: '#f8fafc',
        color: '#475569',
      }}>
        <div style={{
          width: 40,
          height: 40,
          border: '3px solid rgba(203, 213, 225, 0.8)',
          borderTopColor: '#3b82f6',
          borderRadius: '50%',
          animation: 'spin 0.8s linear infinite',
        }} />
        <p>Loading game...</p>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    )
  }

  if (!game) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '1rem',
        background: '#f8fafc',
        color: '#475569',
      }}>
        <AlertCircle size={48} strokeWidth={1} />
        <p>{error || 'Game not found'}</p>
        <button
          style={{
            background: 'linear-gradient(135deg, #667eea, #764ba2)',
            color: 'white',
            border: 'none',
            padding: '0.65rem 1.6rem',
            borderRadius: '12px',
            fontWeight: 600,
            cursor: 'pointer',
          }}
          onClick={() => navigate('/lobby')}
        >
          ← Back to Lobby
        </button>
      </div>
    )
  }

  const players = Array.isArray(game.players) ? game.players : []

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: '#f8fafc', color: '#0f172a' }}>
      {/* Top status bar - using global Navbar for main navigation */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '1rem 2rem',
        background: 'rgba(255, 255, 255, 0.95)',
        borderBottom: '1px solid rgba(203, 213, 225, 0.8)',
        marginTop: '60px', // Account for global Navbar
      }}>
        <button
          style={{
            background: 'rgba(241, 245, 249, 0.8)',
            color: '#0f172a',
            border: '1px solid rgba(203, 213, 225, 0.8)',
            padding: '0.4rem 0.8rem',
            borderRadius: '8px',
            fontWeight: 500,
            fontSize: '0.82rem',
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
          }}
          onClick={() => navigate('/lobby')}
        >
          <ArrowLeft size={16} /> Lobby
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <span style={{
            padding: '0.3rem 0.8rem',
            borderRadius: '8px',
            fontSize: '0.78rem',
            fontWeight: 600,
            textTransform: 'uppercase',
            background: 'rgba(59, 130, 246, 0.15)',
            color: '#3b82f6',
          }}>
            {formatPhase(game.phase)}
          </span>
          <span style={{ color: '#ffd700', fontWeight: 700 }}>
            Pot: ${(game.pot ?? 0).toLocaleString()}
          </span>
        </div>
        <button
          style={{
            background: 'rgba(241, 245, 249, 0.8)',
            color: '#0f172a',
            border: '1px solid rgba(203, 213, 225, 0.8)',
            padding: '0.4rem 0.8rem',
            borderRadius: '8px',
            fontWeight: 500,
            fontSize: '0.82rem',
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
          }}
          onClick={() => { setLogs([]); fetchState(); }}
        >
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem' }}>
        <div style={{
          width: '100%',
          maxWidth: 800,
          background: 'rgba(255, 255, 255, 0.9)',
          border: '1px solid rgba(226, 232, 240, 0.9)',
          borderRadius: '24px',
          padding: '2rem',
        }}>
          <h2 style={{ textAlign: 'center', marginBottom: '1.5rem', fontFamily: "'Inter', sans-serif" }}>
            Game: {gameId}
          </h2>

          {/* Players */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            {players.map((p, i) => (
              <div key={p.player_pk || p.id} style={{
                background: 'rgba(226, 232, 240, 0.5)',
                borderRadius: '12px',
                padding: '1rem',
                textAlign: 'center',
                border: game.current_player_index === i ? '2px solid #10b981' : '1px solid rgba(226, 232, 240, 0.9)',
              }}>
                <div style={{ fontWeight: 600, marginBottom: '0.3rem', textDecoration: p.folded ? 'line-through' : 'none', opacity: p.folded ? 0.4 : 1 }}>
                  <PlayerName name={p.name} />
                </div>
                <div style={{ color: '#ffd700', fontFamily: "'JetBrains Mono', monospace", fontSize: '0.9rem' }}>
                  ${p.chips.toLocaleString()}
                </div>
                {p.current_bet > 0 && !p.folded && (
                  <div style={{ color: '#f59e0b', fontSize: '0.8rem', marginTop: '0.3rem' }}>
                    Bet: ${p.current_bet.toLocaleString()}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Community Cards */}
          <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
            <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '0.5rem' }}>
              Community Cards ({game.community_cards_revealed ?? 0}/{game.config?.community_cards ?? 5})
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
              {Array.from({ length: game.config?.community_cards ?? 5 }).map((_, i) => {
                const isRevealed = i < (game.community_cards_revealed ?? 0)
                const cardValue = Array.isArray(game.community_cards) ? game.community_cards[i] : null
                return (
                  <div key={i} style={{
                    width: 50,
                    height: 70,
                    borderRadius: 8,
                    background: isRevealed && cardValue
                      ? 'linear-gradient(145deg, #ffffff, #f0f0f0)'
                      : 'linear-gradient(145deg, #1a3050, #0d1f35)',
                    border: isRevealed ? '1px solid rgba(0,0,0,0.08)' : '2px solid #2a4a70',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: isRevealed && cardValue ? '0.9rem' : '1.4rem',
                    fontWeight: 700,
                    color: isRevealed && cardValue
                      ? (cardValue.includes('♥') || cardValue.includes('♦') ? '#dc2626' : '#1a1a1a')
                      : 'rgba(255,255,255,0.15)',
                    boxShadow: '0 3px 12px rgba(0,0,0,0.08)',
                  }}>
                    {isRevealed && cardValue ? cardValue : '🂠'}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Winner */}
          {game.winner && (
            <div style={{
              background: 'linear-gradient(135deg, rgba(212,175,55,0.12), rgba(245,158,11,0.12))',
              border: '1px solid rgba(212,175,55,0.35)',
              color: '#b45309',
              padding: '0.8rem 1.2rem',
              borderRadius: '10px',
              fontWeight: 700,
              textAlign: 'center',
              fontSize: '1.05rem',
              marginBottom: '1rem',
            }}>
              🏆 Winner: {game.winner}
            </div>
          )}
        </div>
      </div>

      {/* Event Log */}
      <div style={{
        background: 'rgba(241, 245, 249, 0.9)',
        borderTop: '1px solid rgba(226, 232, 240, 0.9)',
        padding: '1rem 2rem',
        maxHeight: 200,
        overflowY: 'auto',
      }}>
        <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.75rem' }}>
          Event Log
        </h4>
        <div style={{ fontSize: '0.78rem', fontFamily: "'JetBrains Mono', monospace" }}>
          {logs.length === 0 ? (
            <div style={{ color: '#64748b', fontStyle: 'italic', textAlign: 'center', padding: '1rem 0' }}>
              No events yet...
            </div>
          ) : (
            logs.map((log, i) => (
              <div key={i} style={{ padding: '0.25rem 0', color: '#64748b', borderBottom: '1px solid rgba(0,0,0,0.05)' }}>
                {log}
              </div>
            ))
          )}
        </div>
      </div>

      {error && (
        <div
          style={{
            position: 'fixed',
            bottom: '2rem',
            right: '2rem',
            background: 'rgba(239, 68, 68, 0.95)',
            color: 'white',
            padding: '0.8rem 1.5rem',
            borderRadius: '10px',
            fontSize: '0.9rem',
            zIndex: 1000,
            cursor: 'pointer',
          }}
          onClick={() => setError(null)}
        >
          <AlertCircle size={16} style={{ display: 'inline', verticalAlign: 'middle', marginRight: '0.3rem' }} />
          {error} (click to dismiss)
        </div>
      )}
    </div>
  )
}
