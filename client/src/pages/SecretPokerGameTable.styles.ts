import styled from 'styled-components';

/* ===== 共享：居中提示容器（loading / not found） ===== */

export const CenteredMessageContainer = styled.div`
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1rem;
  background: ${({ theme }) => theme.colors.fontColorLight};
  /* TODO: 提取到 theme */ color: #475569;
`;

export const Spinner = styled.div`
  width: 40px;
  height: 40px;
  /* TODO: 提取到 theme */ border: 3px solid rgba(203, 213, 225, 0.8);
  /* TODO: 提取到 theme */ border-top-color: #3b82f6;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
`;

/* ===== 共享：渐变按钮（Back to Lobby / 抽屉开关） ===== */

export const GradientButton = styled.button`
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, /* TODO: 提取到 theme */ #764ba2);
  color: ${({ theme }) => theme.colors.lightestBg};
  border: none;
  padding: 0.65rem 1.6rem;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
`;

/* ===== 主容器 ===== */

export const MainContainer = styled.div`
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  background: ${({ theme }) => theme.colors.fontColorLight};
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

/* ===== 顶部状态栏 ===== */

export const TopBar = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem 2rem;
  /* TODO: 提取到 theme */ background: rgba(255, 255, 255, 0.95);
  /* TODO: 提取到 theme */ border-bottom: 1px solid rgba(203, 213, 225, 0.8);
  margin-top: 60px; /* Account for global Navbar */
`;

/* 共享：次要操作按钮（Lobby / Refresh） */
export const SecondaryActionButton = styled.button`
  /* TODO: 提取到 theme */ background: rgba(241, 245, 249, 0.8);
  color: ${({ theme }) => theme.colors.fontColorDark};
  /* TODO: 提取到 theme */ border: 1px solid rgba(203, 213, 225, 0.8);
  padding: 0.4rem 0.8rem;
  border-radius: 8px;
  font-weight: 500;
  font-size: 0.82rem;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
`;

export const TopBarCenter = styled.div`
  display: flex;
  align-items: center;
  gap: 1rem;
`;

export const PhaseBadge = styled.span`
  padding: 0.3rem 0.8rem;
  border-radius: 8px;
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  /* TODO: 提取到 theme */ background: rgba(59, 130, 246, 0.15);
  /* TODO: 提取到 theme */ color: #3b82f6;
`;

export const PotDisplay = styled.span`
  /* TODO: 提取到 theme */ color: #ffd700;
  font-weight: 700;
`;

export const TopBarRight = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

/* 抽屉开关按钮（窄屏可见，宽屏由 CSS 隐藏） */
export const DrawerToggleButton = styled(GradientButton)`
  padding: 0.4rem 0.8rem;
  border-radius: 8px;
  font-size: 0.82rem;
  align-items: center;
  gap: 0.3rem;
`;

/* ===== 主体布局 ===== */

export const MainLayout = styled.div`
  flex: 1;
  padding: 2rem;
`;

/* ===== 牌桌卡片 ===== */

export const TableCard = styled.div`
  width: 100%;
  /* TODO: 提取到 theme */ background: rgba(255, 255, 255, 0.9);
  /* TODO: 提取到 theme */ border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 24px;
  padding: 2rem;
`;

export const GameTitle = styled.h2`
  text-align: center;
  margin-bottom: 1.5rem;
  font-family: 'Inter', sans-serif;
`;

/* ===== 玩家 ===== */

export const PlayersGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
`;

export const PlayerSeat = styled.div<{ $active: boolean }>`
  /* TODO: 提取到 theme */ background: rgba(226, 232, 240, 0.5);
  border-radius: 12px;
  padding: 1rem;
  text-align: center;
  border: ${({ $active }) =>
    $active
      ? /* TODO: 提取到 theme */ '2px solid #10b981'
      : /* TODO: 提取到 theme */ '1px solid rgba(226, 232, 240, 0.9)'};
`;

export const PlayerNameDisplay = styled.div<{ $folded: boolean }>`
  font-weight: 600;
  margin-bottom: 0.3rem;
  text-decoration: ${({ $folded }) => ($folded ? 'line-through' : 'none')};
  opacity: ${({ $folded }) => ($folded ? 0.4 : 1)};
`;

export const PlayerChips = styled.div`
  /* TODO: 提取到 theme */ color: #ffd700;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
`;

export const PlayerBet = styled.div`
  /* TODO: 提取到 theme */ color: #f59e0b;
  font-size: 0.8rem;
  margin-top: 0.3rem;
`;

/* ===== 公共牌 ===== */

export const CommunityCardsSection = styled.div`
  text-align: center;
  margin-bottom: 1.5rem;
`;

/* 共享：小节标签（Community Cards / 密码学事件流 / 选中事件详情） */
export const SectionLabel = styled.div`
  font-size: 0.75rem;
  /* TODO: 提取到 theme */ color: #64748b;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 0.5rem;
`;

export const SectionLabelTight = styled(SectionLabel)`
  letter-spacing: 0.06em;
  margin-bottom: 0.4rem;
  font-weight: 600;
`;

export const SectionLabelDetail = styled(SectionLabelTight)`
  margin-bottom: 0.5rem;
`;

export const CardsRow = styled.div`
  display: flex;
  gap: 0.5rem;
  justify-content: center;
`;

export const CardDisplay = styled.div<{ $revealed: boolean; $isRed: boolean }>`
  width: 50px;
  height: 70px;
  border-radius: 8px;
  background: ${({ $revealed }) =>
    $revealed
      ? /* TODO: 提取到 theme */ 'linear-gradient(145deg, #ffffff, #f0f0f0)'
      : /* TODO: 提取到 theme */ 'linear-gradient(145deg, #1a3050, #0d1f35)'};
  border: ${({ $revealed }) =>
    $revealed
      ? /* TODO: 提取到 theme */ '1px solid rgba(0,0,0,0.08)'
      : /* TODO: 提取到 theme */ '2px solid #2a4a70'};
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: ${({ $revealed }) => ($revealed ? '0.9rem' : '1.4rem')};
  font-weight: 700;
  color: ${({ $revealed, $isRed }) =>
    $revealed
      ? /* TODO: 提取到 theme */ ($isRed ? '#dc2626' : '#1a1a1a')
      : /* TODO: 提取到 theme */ 'rgba(255,255,255,0.15)'};
  /* TODO: 提取到 theme */ box-shadow: 0 3px 12px rgba(0, 0, 0, 0.08);
`;

/* ===== 赢家横幅 ===== */

export const WinnerBanner = styled.div`
  /* TODO: 提取到 theme */ background: linear-gradient(135deg, rgba(212, 175, 55, 0.12), rgba(245, 158, 11, 0.12));
  /* TODO: 提取到 theme */ border: 1px solid rgba(212, 175, 55, 0.35);
  /* TODO: 提取到 theme */ color: #b45309;
  padding: 0.8rem 1.2rem;
  border-radius: 10px;
  font-weight: 700;
  text-align: center;
  font-size: 1.05rem;
  margin-bottom: 1rem;
`;

/* ===== ZK 可视化面板 ===== */

export const ZkPanel = styled.div`
  background: ${({ theme }) => theme.colors.lightestBg};
  /* TODO: 提取到 theme */ border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 16px;
`;

export const PanelInner = styled.div`
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
`;

export const PanelHeader = styled.div`
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 0.5rem;
`;

export const PanelTitle = styled.h3`
  margin: 0;
  font-size: 1.05rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

export const PanelSubtitle = styled.p`
  margin: 0.2rem 0 0;
  font-size: 0.75rem;
  /* TODO: 提取到 theme */ color: #64748b;
`;

/* 面板关闭按钮（窄屏可见，图标按钮） */
export const PanelCloseButton = styled.button`
  /* TODO: 提取到 theme */ background: rgba(241, 245, 249, 0.8);
  /* TODO: 提取到 theme */ border: 1px solid rgba(203, 213, 225, 0.8);
  border-radius: 8px;
  padding: 0.3rem;
  cursor: pointer;
  /* TODO: 提取到 theme */ color: #475569;
  align-items: center;
  justify-content: center;
`;

export const EventStreamContainer = styled.div`
  height: 300px;
`;

export const EventDetailColumn = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

export const EventTypeRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
`;

export const EventTypeLabel = styled.span`
  font-weight: 700;
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: 0.04em;
`;

export const RevealTokenCards = styled.div`
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  justify-content: center;
  padding: 0.75rem 0.5rem;
  /* TODO: 提取到 theme */ background: rgba(248, 250, 252, 0.6);
  border-radius: 12px;
`;

export const EventMessage = styled.div`
  font-size: 0.8rem;
  /* TODO: 提取到 theme */ color: #475569;
  /* TODO: 提取到 theme */ background: rgba(248, 250, 252, 0.8);
  border-radius: 8px;
  padding: 0.6rem 0.8rem;
`;

export const EmptyDetailPlaceholder = styled.div`
  padding: 1.2rem 0.5rem;
  text-align: center;
  /* TODO: 提取到 theme */ color: #94a3b8;
  font-style: italic;
  font-size: 0.85rem;
  /* TODO: 提取到 theme */ background: rgba(248, 250, 252, 0.6);
  border-radius: 8px;
`;

/* ===== 原始日志 ===== */

export const RawLogSection = styled.div`
  /* TODO: 提取到 theme */ background: rgba(241, 245, 249, 0.9);
  /* TODO: 提取到 theme */ border-top: 1px solid rgba(226, 232, 240, 0.9);
  padding: 0.75rem 2rem;
`;

export const RawLogToggleButton = styled.button`
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  background: none;
  border: none;
  cursor: pointer;
  font-size: 0.82rem;
  font-weight: 600;
  /* TODO: 提取到 theme */ color: #475569;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 0;
`;

export const RawLogContent = styled.div`
  max-height: 200px;
  overflow-y: auto;
  margin-top: 0.75rem;
  font-size: 0.78rem;
  font-family: 'JetBrains Mono', monospace;
`;

export const EmptyLog = styled.div`
  /* TODO: 提取到 theme */ color: #64748b;
  font-style: italic;
  text-align: center;
  padding: 1rem 0;
`;

export const LogEntry = styled.div`
  padding: 0.25rem 0;
  /* TODO: 提取到 theme */ color: #64748b;
  /* TODO: 提取到 theme */ border-bottom: 1px solid rgba(0, 0, 0, 0.05);
`;

/* ===== 错误提示 toast ===== */

export const ErrorToast = styled.div`
  position: fixed;
  bottom: 2rem;
  right: 2rem;
  /* TODO: 提取到 theme */ background: rgba(239, 68, 68, 0.95);
  color: ${({ theme }) => theme.colors.lightestBg};
  padding: 0.8rem 1.5rem;
  border-radius: 10px;
  font-size: 0.9rem;
  z-index: 1000;
  cursor: pointer;
`;
