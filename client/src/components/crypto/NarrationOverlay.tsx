import { Info } from 'lucide-react'

interface NarrationOverlayProps {
  phase: string // 游戏阶段，如 'waiting'/'shuffling'/'preFlop'/'flop'/'turn'/'river'/'showdown' 等
  cryptoEventCount?: number // 已发生的密码学事件数，用于增强叙述
}

// phase → 叙述映射，突出 trustless / 链上验证 / 无庄家 卖点
const NARRATION_MAP: Record<string, string> = {
  waiting: '等待玩家入座。本桌无庄家，发牌完全由多方密码学协议完成。',
  shuffling:
    '洗牌阶段：每位玩家依次重加密牌组并提交 ZK 证明，链上验证通过才进入下一轮，无人能偷看或篡改牌序。',
  shuffleComplete:
    '洗牌完成，所有 ShuffleProof 已链上验证。现在分发手牌，每张牌经多方解密才能显形。',
  preFlopReveal:
    '洗牌完成，所有 ShuffleProof 已链上验证。现在分发手牌，每张牌经多方解密才能显形。',
  preFlop:
    '翻牌前下注轮。手牌仅持有者可解密，链上只存密文，旁观者与对手均无法窥视。',
  flopReveal:
    '翻牌：3 张公共牌依次由对应玩家的 RevealToken 解密，并附 Chaum-Pedersen 证明，证明确实是该玩家的合法解密。',
  flop: '翻牌后下注轮。公共牌已可验证地公开，下注基于真实牌力。',
  turnReveal: '转牌：第 4 张公共牌解密，同样附 ZK 证明。',
  turn: '转牌后下注轮。',
  riverReveal: '河牌：最后一张公共牌解密。',
  river: '河牌后下注轮，最后一轮下注。',
  showdownReveal:
    '摊牌：所有未弃牌玩家揭示手牌，链上验证每张牌的解密证明，确认无作弊。',
  showdown: '摊牌结算：手牌评估与边池分配均在链上完成，结果可验证。',
  handComplete: '本局结束。整局从洗牌到结算全程 trustless，无任何可信第三方。',
}

// Demo 叙事层：根据当前游戏 phase 显示一句人话叙述，向评委解释该步骤如何保证公平
export default function NarrationOverlay({
  phase,
  cryptoEventCount = 0,
}: NarrationOverlayProps) {
  // 取出当前阶段对应的叙述，未匹配时使用默认文案
  const narration = NARRATION_MAP[phase] ?? `当前阶段：${phase}。全程链上可验证。`
  const hasCryptoCount = cryptoEventCount > 0

  return (
    <div
      style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.6rem',
        background: 'rgba(59, 130, 246, 0.08)',
        borderLeft: '3px solid #3b82f6',
        borderRadius: '8px',
        padding: '0.7rem 1rem',
        // 有密码学计数时多留底部空间，避免与右下角小字重叠
        paddingBottom: hasCryptoCount ? '1.5rem' : '0.7rem',
      }}
    >
      <Info
        size={18}
        color="#3b82f6"
        style={{ flexShrink: 0, marginTop: 2 }}
      />
      <p
        // key 随 phase 变化触发重挂载，从而重放淡入动画
        key={phase}
        style={{
          flex: 1,
          margin: 0,
          color: '#0f172a',
          fontWeight: 700,
          fontSize: '0.9rem',
          lineHeight: 1.5,
          animation: 'fadeIn 0.4s ease-out',
        }}
      >
        {narration}
      </p>
      {hasCryptoCount && (
        <span
          style={{
            position: 'absolute',
            bottom: '0.3rem',
            right: '0.8rem',
            fontSize: '0.72rem',
            color: '#10b981',
            fontWeight: 600,
          }}
        >
          已验证 {cryptoEventCount} 个密码学操作
        </span>
      )}
      <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(-2px); } to { opacity: 1; transform: translateY(0); } }`}</style>
    </div>
  )
}
