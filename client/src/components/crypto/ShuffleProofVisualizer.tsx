import type { ReactNode } from 'react'
import { ShieldCheck, CheckCircle2 } from 'lucide-react'
import { useContentContext } from '../../context/content/contentContext'

interface ShuffleProofVisualizerProps {
  proof?: {
    sum_c1_commit?: string
    sum_c2_commit?: string
    nonce?: string
  } | null
  verified?: boolean | null
}

function truncateHex(hex: string | undefined, prefix = 10): string {
  if (!hex) return '—'
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length <= prefix) return `0x${clean}`
  return `0x${clean.slice(0, prefix)}…`
}

const COLOR_BLUE = '#3b82f6'
const COLOR_GREEN = '#10b981'
const COLOR_RED = '#ef4444'
const COLOR_HEX = '#64748b'

export default function ShuffleProofVisualizer({ proof, verified }: ShuffleProofVisualizerProps) {
  const { getLocalizedString: t } = useContentContext()

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
      <div style={{ marginBottom: '0.75rem' }}>
        <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700, color: '#0f172a' }}>
          {t('shuffle-proof_title')}
        </h3>
        <p style={{ margin: '0.2rem 0 0', fontSize: '0.78rem', color: COLOR_BLUE, fontWeight: 600 }}>
          {t('shuffle-proof_subtitle')}
        </p>
      </div>

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
          {t('shuffle-proof_placeholder')}
        </div>
      ) : (
        <>
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
              {t('shuffle-proof_commitment-layer')}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <HexRow label="sum_c1_commit" value={truncateHex(proof.sum_c1_commit)} />
              <HexRow label="sum_c2_commit" value={truncateHex(proof.sum_c2_commit)} />
            </div>
          </div>

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
              {t('shuffle-proof_proof-layer')}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <ProofRow icon={<ShieldCheck size={16} color={COLOR_BLUE} />} name="combined_schnorr_proof" desc={t('shuffle-proof_combined')} />
              <ProofRow icon={<ShieldCheck size={16} color={COLOR_BLUE} />} name="sum_c1_schnorr_proof" desc={t('shuffle-proof_c1-only')} />
              <ProofRow icon={<ShieldCheck size={16} color={COLOR_BLUE} />} name="sum_c2_schnorr_proof" desc={t('shuffle-proof_c2-only')} />
            </div>
          </div>

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
              {t('shuffle-proof_anti-replay')}
            </div>
            <HexRow label="nonce" value={truncateHex(proof.nonce)} />
          </div>
        </>
      )}

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
          {t('shuffle-proof_highlights')}
        </div>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <HighlightItem text={t('shuffle-proof_highlight-1')} />
          <HighlightItem text={t('shuffle-proof_highlight-2')} />
          <HighlightItem text={t('shuffle-proof_highlight-3')} />
        </ul>
      </div>
    </div>
  )
}

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

function HighlightItem({ text }: { text: string }) {
  return (
    <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
      <CheckCircle2 size={14} color={COLOR_GREEN} style={{ flexShrink: 0 }} />
      <span style={{ fontSize: '0.75rem', color: '#475569' }}>{text}</span>
    </li>
  )
}
