import styled from 'styled-components';

// 离开牌桌时的全屏遮罩
export const LeavingOverlay = styled.div`
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.7);
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  z-index: 9999;
`;

// 玩家操作签名中的全屏遮罩
export const ActionLoadingOverlay = styled.div`
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.6);
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  z-index: 9998;
  pointer-events: auto;
`;
