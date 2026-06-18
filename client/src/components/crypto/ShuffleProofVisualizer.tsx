import type { ReactNode } from 'react'
import { ShieldCheck, CheckCircle2 } from 'lucide-react'

// ShuffleProofVisualizer 组件的 Props
interface ShuffleProofVisualizerProps {
  // 证明数据（可选，无则展示占位说明）
  proof?: {
    sum_c1_commit?: string // hex
    sum_c2_commit?: string // hex
    nonce?: string // hex
  } | null
  // 关联的 crypto 事件（用于显示验证状态）
  verified?: boolean | null
}

// 将 hex 字符串截断为前 10 字符 + … 的形式，便于展示
function truncateHex(hex: string | undefined, prefix = 10): string {
  if (!hex) return '—'
  // 去除可能的 0x 前缀后再截断
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length <= prefix) return `0x${clean}`
  return `0x${clean.slice(0, prefix)}…`
}

// 颜色常量
const COLOR_BLUE = '#3b82f6'
const COLOR_GREEN = '#10b981'
const COLOR_RED = '#ef4444'
const COLOR_HEX = '#64748b'

export default function ShuffleProofVisualizer({ proof, verified }: ShuffleProofVisualizerProps) {
  // 根据 verified 状态决定边框颜色
  const borderColor =
    verified === true
      ? COLOR_GREEN
      : verified === false
        ? COLOR_RED
        : 'rgba(226, 232, 240, 0.9)'

  return (
    <div
      style={{
        background: '#ffffff',
        borderRadius: '12px',
        padding: '1rem',
        border: `1px solid ${borderColor}`,
        boxShadow: '0 3px 12px rgba(0,0,0,0.05)',
        fontFamily: "'Inter', sans-serif",
        color: '#0f172a',
      }}
    >
      {/* 标题区 */}
      <div style={{ marginBottom: '0.75rem' }}>
        <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#0f172a' }}>
          ShuffleProof 结构
        </h3>
        <p style={{ margin: '0.2rem 0 0', fontSize: '0.78rem', color: COLOR_BLUE, fontWeight: 600 }}>
          3 层 Schnorr 防置换映射攻击
        </p>
      </div>

      {/* 主体：proof 为 null 时显示占位 */}
      {proof === null || proof === undefined ? (
        <div
          style={{
            padding: '1.2rem 0.5rem',
            textAlign: 'center',
            color: '#94a3b8',
            fontStyle: 'italic',
            fontSize: '0.85rem',
          }}
        >
          暂无洗牌证明数据，等待玩家提交…
        </div>
      ) : (
        <>
          {/* 1. 承诺层 */}
          <div style={{ marginBottom: '0.75rem' }}>
            <div
              style={{
                fontSize: '0.7rem',
                color: '#94a3b8',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                marginBottom: '0.4rem',
                fontWeight: 600,
              }}
            >
              承诺层 · 输入密文加权和承诺
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <HexRow label="sum_c1_commit" value={truncateHex(proof.sum_c1_commit)} />
              <HexRow label="sum_c2_commit" value={truncateHex(proof.sum_c2_commit)} />
            </div>
          </div>

          {/* 2. 证明层：3 个 Schnorr 证明 */}
          <div style={{ marginBottom: '0.75rem' }}>
            <div
              style={{
                fontSize: '0.7rem',
                color: '#94a3b8',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                marginBottom: '0.4rem',
                fontWeight: 600,
              }}
            >
              证明层 · GeneralizedSchnorrProof ×3
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <ProofRow icon={<ShieldCheck size={16} color={COLOR_BLUE} />} name="combined_schnorr_proof" desc="c1+c2 合并证明" />
              <ProofRow icon={<ShieldCheck size={16} color={COLOR_BLUE} />} name="sum_c1_schnorr_proof" desc="仅 c1 证明" />
              <ProofRow icon={<ShieldCheck size={16} color={COLOR_BLUE} />} name="sum_c2_schnorr_proof" desc="仅 c2 证明" />
            </div>
          </div>

          {/* 3. 防重放 */}
          <div style={{ marginBottom: '0.75rem' }}>
            <div
              style={{
                fontSize: '0.7rem',
                color: '#94a3b8',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                marginBottom: '0.4rem',
                fontWeight: 600,
              }}
            >
              防重放 · anti-replay nonce
            </div>
            <HexRow label="nonce" value={truncateHex(proof.nonce)} />
          </div>
        </>
      )}

      {/* 底部：技术亮点 */}
      <div
        style={{
          marginTop: '0.5rem',
          paddingTop: '0.75rem',
          borderTop: '1px dashed rgba(226, 232, 240, 0.9)',
        }}
      >
        <div
          style={{
            fontSize: '0.7rem',
            color: '#94a3b8',
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            marginBottom: '0.4rem',
            fontWeight: 600,
          }}
        >
          技术亮点
        </div>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <HighlightItem text="3 层 Schnorr 证明防止置换映射攻击" />
          <HighlightItem text="Fiat-Shamir 非交互式零知识证明" />
          <HighlightItem text="Sui 原生 BLS12-381 链上验证" />
        </ul>
      </div>
    </div>
  )
}

// hex 行：左侧标签，右侧 monospace 截断值
function HexRow({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '0.5rem',
        background: 'rgba(248, 250, 252, 0.8)',
        borderRadius: '6px',
        padding: '0.35rem 0.55rem',
      }}
    >
      <span style={{ fontSize: '0.75rem', color: '#475569', fontWeight: 500 }}>{label}</span>
      <span
        style={{
          fontSize: '0.75rem',
          fontFamily: "'JetBrains Mono', monospace",
          color: COLOR_HEX,
        }}
      >
        {value}
      </span>
    </div>
  )
}

// 证明行：图标 + 名称 + 用途说明
function ProofRow({ icon, name, desc }: { icon: ReactNode; name: string; desc: string }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        background: 'rgba(248, 250, 252, 0.8)',
        borderRadius: '6px',
        padding: '0.35rem 0.55rem',
      }}
    >
      <span style={{ display: 'inline-flex', flexShrink: 0 }}>{icon}</span>
      <span
        style={{
          fontSize: '0.75rem',
          fontFamily: "'JetBrains Mono', monospace",
          color: '#0f172a',
          fontWeight: 600,
        }}
      >
        {name}
      </span>
      <span style={{ fontSize: '0.72rem', color: COLOR_HEX, marginLeft: 'auto' }}>{desc}</span>
    </div>
  )
}

// 技术亮点条目
function HighlightItem({ text }: { text: string }) {
  return (
    <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
      <CheckCircle2 size={14} color={COLOR_GREEN} style={{ flexShrink: 0 }} />
      <span style={{ fontSize: '0.75rem', color: '#475569' }}>{text}</span>
    </li>
  )
}
