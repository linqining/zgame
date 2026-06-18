import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, RefreshCw, AlertCircle, ChevronRight, ChevronDown, X, Eye } from 'lucide-react'
import api, { GameState } from '../api/secretPokerClient'
import { PlayerName } from '../components/game/PlayerName'
import { gameWsClient } from '../api/wsClient'
import { CryptoEvent } from '../types/game'
// ZK 密码学可视化组件
import NarrationOverlay from '../components/crypto/NarrationOverlay'
import CryptoEventStream from '../components/crypto/CryptoEventStream'
import { OnchainVerificationBadge } from '../components/crypto/OnchainVerificationBadge'
import EncryptedCard from '../components/crypto/EncryptedCard'
import ShuffleProofVisualizer from '../components/crypto/ShuffleProofVisualizer'

export default function GameTable() {
  const { gameId } = useParams<{ gameId: string }>()
  const navigate = useNavigate()
  const [game, setGame] = useState<GameState | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  // ZK 密码学事件收集（用于可视化面板，保留最近 100 条）
  const [cryptoEvents, setCryptoEvents] = useState<CryptoEvent[]>([])
  // 当前选中的密码学事件（用于详情区渲染）
  const [selectedEvent, setSelectedEvent] = useState<CryptoEvent | null>(null)
  // 窄屏抽屉开关（宽屏下面板始终可见，CSS 控制；窄屏默认收起，符合"折叠为可展开抽屉"）
  const [showPanel, setShowPanel] = useState(false)
  // 原始日志折叠开关（默认折叠，避免与可视化面板信息重复）
  const [showRawLog, setShowRawLog] = useState(false)

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
      onCryptoEvent: (ev) => {
        // 收集 crypto 事件（保留最近 100 条），用于可视化面板
        setCryptoEvents(prev => [...prev.slice(-99), ev])
        console.log('[CryptoEvent]', ev)
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
      {/* 响应式布局样式：宽屏（≥1024px）双栏内联；窄屏右栏变为右侧抽屉 */}
      <style>{`
        .zk-layout { display: flex; flex-direction: row; gap: 1.5rem; }
        .zk-left { flex: 0 0 60%; min-width: 0; }
        .zk-panel { position: relative; flex: 0 0 40%; min-width: 0; }
        .zk-drawer-btn { display: none; }
        .zk-panel-close { display: none; }
        .zk-backdrop { display: none; }
        @media (max-width: 1023px) {
          .zk-layout { flex-direction: column; gap: 1rem; }
          .zk-left { flex: 1 1 auto; width: 100%; }
          .zk-panel {
            position: fixed;
            top: 0; right: 0; bottom: 0;
            width: 380px; max-width: 85vw;
            background: #ffffff;
            z-index: 200;
            box-shadow: -8px 0 24px rgba(0,0,0,0.15);
            transform: translateX(100%);
            transition: transform 0.3s ease;
            overflow-y: auto;
            flex: none;
          }
          .zk-panel.is-open { transform: translateX(0); }
          .zk-drawer-btn { display: inline-flex; }
          .zk-panel-close { display: inline-flex; }
          .zk-backdrop { display: block; position: fixed; inset: 0; background: rgba(0,0,0,0.3); z-index: 150; }
        }
      `}</style>

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
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {/* 窄屏抽屉开关按钮（宽屏通过 CSS 隐藏） */}
          <button
            className="zk-drawer-btn"
            onClick={() => setShowPanel(v => !v)}
            style={{
              background: 'linear-gradient(135deg, #667eea, #764ba2)',
              color: 'white',
              border: 'none',
              padding: '0.4rem 0.8rem',
              borderRadius: '8px',
              fontWeight: 600,
              fontSize: '0.82rem',
              cursor: 'pointer',
              alignItems: 'center',
              gap: '0.3rem',
            }}
          >
            <Eye size={14} /> {showPanel ? '收起' : 'ZK 可视化'}
          </button>
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
      </div>

      {/* 主体：双栏布局（宽屏左 60% 牌桌 / 右 40% 可视化；窄屏右栏变抽屉） */}
      <div className="zk-layout" style={{ flex: 1, padding: '2rem' }}>
        {/* 左栏：牌桌内容（状态栏、玩家、公共牌、winner） */}
        <div className="zk-left">
          <div style={{
            width: '100%',
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

        {/* 窄屏抽屉遮罩（宽屏通过 CSS 隐藏） */}
        {showPanel && <div className="zk-backdrop" onClick={() => setShowPanel(false)} />}

        {/* 右栏：ZK 密码学可视化面板（宽屏内联 40%；窄屏右侧抽屉，由 showPanel 控制滑入） */}
        <div
          className={`zk-panel ${showPanel ? 'is-open' : ''}`}
          style={{
            background: '#ffffff',
            border: '1px solid rgba(226, 232, 240, 0.9)',
            borderRadius: '16px',
          }}
        >
          <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* 面板标题 + 副标题 + 关闭按钮（窄屏可见） */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.5rem' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#0f172a' }}>
                  ZK 密码学可视化
                </h3>
                <p style={{ margin: '0.2rem 0 0', fontSize: '0.75rem', color: '#64748b' }}>
                  Sui 链上可验证公平博弈
                </p>
              </div>
              <button
                className="zk-panel-close"
                onClick={() => setShowPanel(false)}
                style={{
                  background: 'rgba(241, 245, 249, 0.8)',
                  border: '1px solid rgba(203, 213, 225, 0.8)',
                  borderRadius: '8px',
                  padding: '0.3rem',
                  cursor: 'pointer',
                  color: '#475569',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
                title="收起"
              >
                <X size={16} />
              </button>
            </div>

            {/* NarrationOverlay：根据当前 phase 显示人话叙述 */}
            <NarrationOverlay phase={game.phase} cryptoEventCount={cryptoEvents.length} />

            {/* CryptoEventStream：固定高度 300px 可滚动 */}
            <div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.4rem', fontWeight: 600 }}>
                密码学事件流
              </div>
              <div style={{ height: 300 }}>
                <CryptoEventStream
                  events={cryptoEvents}
                  onSelect={(ev) => setSelectedEvent(ev)}
                  selectedTimestamp={selectedEvent?.timestamp}
                />
              </div>
            </div>

            {/* 选中事件详情区 */}
            <div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.5rem', fontWeight: 600 }}>
                选中事件详情
              </div>
              {selectedEvent ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {/* 事件类型 + 链上验证徽章 */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.85rem', color: '#0f172a', letterSpacing: '0.04em' }}>
                      {selectedEvent.event_type.toUpperCase()}
                    </span>
                    <OnchainVerificationBadge
                      txDigest={selectedEvent.tx_digest}
                      verified={selectedEvent.verified}
                    />
                  </div>

                  {/* shuffle 事件：渲染 ShuffleProofVisualizer（proof 暂传 null，后端未广播完整 proof 字节） */}
                  {selectedEvent.event_type === 'shuffle' && (
                    <ShuffleProofVisualizer proof={null} verified={selectedEvent.verified} />
                  )}

                  {/* reveal_token 事件：渲染一组 EncryptedCard 演示（密文态，展示组件形态） */}
                  {selectedEvent.event_type === 'reveal_token' && (
                    <div style={{
                      display: 'flex',
                      gap: '0.5rem',
                      flexWrap: 'wrap',
                      justifyContent: 'center',
                      padding: '0.75rem 0.5rem',
                      background: 'rgba(248, 250, 252, 0.6)',
                      borderRadius: 12,
                    }}>
                      {[0, 1, 2].map((offset) => (
                        <EncryptedCard
                          key={offset}
                          cardIndex={(selectedEvent.card_index ?? 0) + offset}
                          decryptedValue={null}
                          ciphertextPreview={null}
                          size="md"
                        />
                      ))}
                    </div>
                  )}

                  {/* 其它事件类型（remask/leave/reconstruct）：显示消息文案 */}
                  {selectedEvent.event_type !== 'shuffle' && selectedEvent.event_type !== 'reveal_token' && selectedEvent.message && (
                    <div style={{
                      fontSize: '0.8rem',
                      color: '#475569',
                      background: 'rgba(248, 250, 252, 0.8)',
                      borderRadius: 8,
                      padding: '0.6rem 0.8rem',
                    }}>
                      {selectedEvent.message}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{
                  padding: '1.2rem 0.5rem',
                  textAlign: 'center',
                  color: '#94a3b8',
                  fontStyle: 'italic',
                  fontSize: '0.85rem',
                  background: 'rgba(248, 250, 252, 0.6)',
                  borderRadius: 8,
                }}>
                  点击上方事件查看密码学证明详情
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 原始日志（可折叠，默认折叠，避免与可视化面板信息重复） */}
      <div style={{
        background: 'rgba(241, 245, 249, 0.9)',
        borderTop: '1px solid rgba(226, 232, 240, 0.9)',
        padding: '0.75rem 2rem',
      }}>
        <button
          onClick={() => setShowRawLog(v => !v)}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontSize: '0.82rem',
            fontWeight: 600,
            color: '#475569',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            padding: 0,
          }}
        >
          {showRawLog ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          原始日志
        </button>
        {showRawLog && (
          <div style={{ maxHeight: 200, overflowY: 'auto', marginTop: '0.75rem', fontSize: '0.78rem', fontFamily: "'JetBrains Mono', monospace" }}>
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
        )}
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
