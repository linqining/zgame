import { useState, useEffect } from 'react'
import { Lock } from 'lucide-react'

interface EncryptedCardProps {
  // 密文摘要（ElGamal c1/c2 的 hex 前 8 字符）
  ciphertextPreview?: { c1: string; c2: string } | null
  // 解密后的明文牌面（如 "A♥" "K♠" "10♦"），为 null/undefined 表示尚未解密
  decryptedValue: string | null
  // 解密者玩家标识（pk 截断或名字）
  decryptedBy?: string | null
  // 卡片索引
  cardIndex?: number
  size?: 'sm' | 'md' // 默认 md
}

// 尺寸配置：md 56x80 / sm 40x56
const SIZE_MAP = {
  sm: { w: 40, h: 56, fontMain: '0.72rem', fontSub: '0.48rem', lockSize: 12 },
  md: { w: 56, h: 80, fontMain: '1.05rem', fontSub: '0.6rem', lockSize: 16 },
} as const

// 卡片所处阶段：密文态 / 翻转中 / 解密态
type CardPhase = 'encrypted' | 'flipping' | 'decrypted'

// 将 hex 截断为前 8 字符，超出则追加 ".."，统一带 0x 前缀
function truncateHex(hex: string): string {
  const v = hex.startsWith('0x') ? hex : `0x${hex}`
  return v.length > 8 ? `${v.slice(0, 8)}..` : v
}

// 根据花色返回颜色：红色 ♥♦ / 黑色 ♠♣
function suitColor(value: string): string {
  if (value.includes('♥') || value.includes('♦')) return '#dc2626'
  return '#1a1a1a'
}

export default function EncryptedCard({
  ciphertextPreview,
  decryptedValue,
  decryptedBy,
  cardIndex,
  size = 'md',
}: EncryptedCardProps) {
  const s = SIZE_MAP[size]
  // 初始阶段：挂载时若已解密则直接处于解密态（不播放动画）
  const [phase, setPhase] = useState<CardPhase>(decryptedValue ? 'decrypted' : 'encrypted')
  // 上一轮的 decryptedValue，用于检测 空 → 非空 的转变
  const [prevValue, setPrevValue] = useState<string | null>(decryptedValue ?? null)

  useEffect(() => {
    // 检测从密文态切换到解密态：触发翻转动画
    if (prevValue == null && decryptedValue != null) {
      setPhase('flipping')
      const t = setTimeout(() => setPhase('decrypted'), 600)
      setPrevValue(decryptedValue)
      return () => clearTimeout(t)
    }
    // 其它变化仅同步状态，不触发动画
    if (prevValue !== decryptedValue) {
      setPrevValue(decryptedValue ?? null)
      setPhase(decryptedValue ? 'decrypted' : 'encrypted')
    }
  }, [decryptedValue, prevValue])

  // 翻转容器 className：根据阶段切换以触发 / 保持翻转
  const flipperClass = [
    'enc-card-flipper',
    phase === 'flipping' ? 'is-flipping' : '',
    phase === 'decrypted' ? 'is-flipped' : '',
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <div style={{ perspective: 600 }}>
      <style>{`
        @keyframes encCardFlip {
          0% { transform: rotateY(0deg); }
          100% { transform: rotateY(180deg); }
        }
        .enc-card-flipper {
          position: relative;
          width: ${s.w}px;
          height: ${s.h}px;
          transform-style: preserve-3d;
        }
        .enc-card-flipper.is-flipping {
          animation: encCardFlip 0.6s ease-in-out forwards;
        }
        .enc-card-flipper.is-flipped {
          transform: rotateY(180deg);
        }
        .enc-card-face {
          position: absolute;
          inset: 0;
          border-radius: 8px;
          backface-visibility: hidden;
          -webkit-backface-visibility: hidden;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          box-shadow: 0 3px 12px rgba(0,0,0,0.12);
          overflow: hidden;
          box-sizing: border-box;
        }
        .enc-card-face--back {
          transform: rotateY(180deg);
        }
      `}</style>

      <div className={flipperClass}>
        {/* 正面：密文态 */}
        <div
          className="enc-card-face"
          style={{
            background: 'linear-gradient(145deg, #1a3050, #0d1f35)',
            border: '2px solid #2a4a70',
            color: 'rgba(255,255,255,0.85)',
          }}
        >
          {/* 左上角索引角标 */}
          {cardIndex != null && (
            <span
              style={{
                position: 'absolute',
                top: 2,
                left: 4,
                fontSize: s.fontSub,
                color: 'rgba(255,255,255,0.45)',
                fontFamily: "'JetBrains Mono', monospace",
                lineHeight: 1,
              }}
            >
              #{cardIndex}
            </span>
          )}
          <Lock size={s.lockSize} strokeWidth={2} style={{ opacity: 0.85 }} />
          <span
            style={{
              fontSize: s.fontMain,
              fontWeight: 700,
              letterSpacing: '0.08em',
              marginTop: 2,
              lineHeight: 1,
            }}
          >
            ENC
          </span>
          {/* 底部 c1/c2 密文摘要 */}
          {ciphertextPreview && (
            <div
              style={{
                position: 'absolute',
                bottom: 2,
                left: 0,
                right: 0,
                textAlign: 'center',
                fontSize: s.fontSub,
                fontFamily: "'JetBrains Mono', monospace",
                color: 'rgba(255,255,255,0.45)',
                lineHeight: 1.1,
                padding: '0 3px',
              }}
            >
              <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                c1:{truncateHex(ciphertextPreview.c1)}
              </div>
              <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                c2:{truncateHex(ciphertextPreview.c2)}
              </div>
            </div>
          )}
        </div>

        {/* 背面：解密态 */}
        <div
          className="enc-card-face enc-card-face--back"
          style={{
            background: 'linear-gradient(145deg, #ffffff, #f0f0f0)',
            border: '1px solid rgba(0,0,0,0.08)',
            color: suitColor(decryptedValue ?? ''),
          }}
        >
          {/* 左上角索引角标 */}
          {cardIndex != null && (
            <span
              style={{
                position: 'absolute',
                top: 2,
                left: 4,
                fontSize: s.fontSub,
                color: 'rgba(0,0,0,0.35)',
                fontFamily: "'JetBrains Mono', monospace",
                lineHeight: 1,
              }}
            >
              #{cardIndex}
            </span>
          )}
          <span style={{ fontSize: s.fontMain, fontWeight: 800, lineHeight: 1 }}>
            {decryptedValue ?? ''}
          </span>
          {/* 底部解密者标识 */}
          {decryptedBy && (
            <span
              style={{
                position: 'absolute',
                bottom: 3,
                left: 0,
                right: 0,
                textAlign: 'center',
                fontSize: s.fontSub,
                color: '#059669',
                lineHeight: 1.15,
                padding: '0 3px',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              decrypted by {decryptedBy}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
