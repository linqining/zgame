import type { CSSProperties } from 'react'
import { ExternalLink, ShieldCheck, Clock } from 'lucide-react'
import { useContentContext } from '../../context/content/contentContext'

interface OnchainVerificationBadgeProps {
  txDigest: string | null
  verified?: boolean // 是否验证通过，影响颜色
  network?: 'testnet' | 'mainnet' // 默认 testnet
  compact?: boolean // 紧凑模式，只显示图标
}

// 基础徽章样式：圆角 6px 小徽章，与 SecretPokerGameTable 内联风格一致
const baseStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: '0.3rem',
  padding: '0.2rem 0.5rem',
  borderRadius: '6px',
  fontSize: '0.72rem',
  fontFamily: 'monospace',
  lineHeight: 1.2,
  whiteSpace: 'nowrap',
  textDecoration: 'none',
  userSelect: 'none',
}

// 三种状态颜色
const greenStyle: CSSProperties = {
  background: 'rgba(16,185,129,0.12)',
  color: '#059669',
}
const redStyle: CSSProperties = {
  background: 'rgba(239,68,68,0.12)',
  color: '#dc2626',
}
const grayStyle: CSSProperties = {
  background: 'rgba(100,116,139,0.12)',
  color: '#64748b',
}

// 截断 digest：前 6 + 后 4 字符
function truncateDigest(digest: string): string {
  if (digest.length <= 10) return digest
  return `${digest.slice(0, 6)}…${digest.slice(-4)}`
}

export function OnchainVerificationBadge({
  txDigest,
  verified = false,
  network = 'testnet',
  compact = false,
}: OnchainVerificationBadgeProps) {
  const { getLocalizedString: t } = useContentContext()
  // 无 txDigest：显示灰色 pending 状态，不可点击
  if (!txDigest) {
    return (
      <span
        style={{ ...baseStyle, ...grayStyle, cursor: 'default' }}
        title={t('crypto_pending-onchain')}
      >
        <Clock size={12} />
        {!compact && <span>{t('crypto_pending-onchain')}</span>}
      </span>
    )
  }

  // 有 txDigest：渲染为可点击链接，跳转到 SuiVision 浏览器
  const href = `https://${network === 'mainnet' ? '' : 'testnet.'}suivision.xyz/txblock/${txDigest}`
  // verified=true 用 ShieldCheck 图标 + 绿色；verified=false 用 ExternalLink 图标 + 红色
  const Icon = verified ? ShieldCheck : ExternalLink
  const colorStyle = verified ? greenStyle : redStyle

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={txDigest}
      style={{ ...baseStyle, ...colorStyle, cursor: 'pointer' }}
    >
      <Icon size={12} />
      {!compact && <span>{truncateDigest(txDigest)}</span>}
    </a>
  )
}

export default OnchainVerificationBadge
