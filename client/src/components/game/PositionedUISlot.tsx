import styled from 'styled-components';

interface PositionedUISlotProps {
  width?: string;
  height?: string;
  top?: string;
  right?: string;
  bottom?: string;
  left?: string;
  origin?: string;
  scale?: string;
}

export const PositionedUISlot = styled.div.withConfig({
  shouldForwardProp: (prop) => !['width', 'height', 'top', 'right', 'bottom', 'left', 'origin', 'scale'].includes(prop),
})<PositionedUISlotProps>`
  width: ${({ width }) => width || 'auto'};
  height: ${({ height }) => height || 'auto'};
  position: absolute;
  top: ${({ top }) => top};
  right: ${({ right }) => right};
  bottom: ${({ bottom }) => bottom};
  left: ${({ left }) => left};
  transform-origin: ${({ origin }) => origin || 'top left'};
  -webkit-backface-visibility: hidden;
  backface-visibility: hidden;

  @media screen and (max-width: 1068px) {
    transform: ${({ scale }) => `scale(${+(scale ?? '1') + 0.3})`};
  }

  @media screen and (max-width: 968px) {
    transform: ${({ scale }) => `scale(${+(scale ?? '1') + 0.25})`};
  }

  @media screen and (max-width: 868px) {
    transform: ${({ scale }) => `scale(${+(scale ?? '1') + 0.2})`};
  }

  @media screen and (max-width: 812px) {
    transform: ${({ scale }) => `scale(${+(scale ?? '1') + 0.15})`};
  }

  @media screen and (max-width: 668px) {
    transform: ${({ scale }) => `scale(${+(scale ?? '1') + 0.1})`};
  }

  @media screen and (max-width: 648px) {
    transform: ${({ scale }) => `scale(${+(scale ?? '1') + 0.05})`};
  }

  @media screen and (max-width: 568px) {
    transform: ${({ scale }) => `scale(${scale ?? '1'})`};
  }
`;
