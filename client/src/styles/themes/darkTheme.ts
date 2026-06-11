// 深色主题配色（Secret Poker 风格）
export const darkTheme = {
  // 背景色
  colors: {
    // 主背景
    primaryBg: '#0a0e17',
    secondaryBg: '#0c0e12',
    lightestBg: 'rgba(10, 14, 23, 0.95)',

    // 卡片背景
    cardBg: 'rgba(26, 31, 46, 0.9)',
    cardBorder: 'rgba(45, 55, 72, 0.6)',

    // 文字色
    text: '#f0f4f8',
    textSecondary: '#94a3b8',
    textMuted: '#64748b',

    // 强调色
    primaryCta: '#667eea',      // 紫蓝色
    secondaryCta: '#764ba2',   // 深紫色
    accent: '#06b6d4',         // 青色
    success: '#10b981',         // 绿色
    warning: '#f59e0b',         // 橙色
    error: '#ef4444',           // 红色

    // 渐变
    gradient: 'linear-gradient(135deg, #667eea, #764ba2)',
    gradientHover: 'linear-gradient(135deg, #7b8ff0, #8559ad)',

    // 毛玻璃效果
    glassBg: 'rgba(10, 14, 23, 0.7)',
    glassBorder: 'rgba(45, 55, 72, 0.5)',
  },

  // 圆角
  borderRadius: {
    sm: '8px',
    md: '12px',
    lg: '16px',
    xl: '24px',
  },

  // 阴影
  shadows: {
    sm: '0 4px 20px rgba(0, 0, 0, 0.25)',
    md: '0 8px 40px rgba(0, 0, 0, 0.35)',
    lg: '0 12px 50px rgba(0, 0, 0, 0.5)',
    glow: '0 0 20px rgba(102, 126, 234, 0.3)',
  },
};

export type DarkTheme = typeof darkTheme;

// 判断是否为深色主题路由（已废弃，整体改为亮色主题）
export function isDarkRoute(_pathname: string): boolean {
  return false;
}
