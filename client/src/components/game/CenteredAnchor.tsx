import styled from 'styled-components';

interface CenteredAnchorProps {
  width?: string;
  height?: string;
}

export const CenteredAnchor = styled.div.withConfig({
  shouldForwardProp: (prop) => !['width', 'height'].includes(prop),
})<CenteredAnchorProps>`
  width: ${({ width }) => width};
  height: ${({ height }) => height};
  position: absolute;
  top: 50%;
  left: 50%;
`;
