import React from 'react';
import styled from 'styled-components';
import CloseIcon from '../icons/CloseIcon';

const StyledCloseIcon = styled.div`
  display: inline-block;
  cursor: pointer;
  outline: none;
  border: 2px solid rgba(0, 0, 0, 0);

  &:focus {
    outline: none;
    border: 2px solid ${({ theme }) => theme.colors.primaryCtaDarker};
    border-radius: 50%;
  }
`;

interface CloseButtonProps {
  clickHandler: () => void;
  autoFocus?: boolean;
}

const CloseButton: React.FC<CloseButtonProps> = ({ clickHandler }) => {
  return (
    <StyledCloseIcon
      onClick={clickHandler}
      onKeyDown={(e) => {
        if (e.keyCode === 13) clickHandler();
      }}
      tabIndex={0}
    >
      <CloseIcon />
    </StyledCloseIcon>
  );
};

export default CloseButton;
