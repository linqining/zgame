import React from 'react';
import EyeIcon from '../icons/EyeIcon';
import styled from 'styled-components';

const StyledShowPasswordButton = styled.div`
  position: absolute;
  z-index: 40;
  right: 15px;
  bottom: 3px;
  cursor: pointer;

  svg {
    width: 30px;
  }
`;

const togglePasswordVisibility = (ref: React.RefObject<HTMLInputElement | null>) => {
  if (ref.current?.type === 'password') {
    ref.current.type = 'text';
  } else if (ref.current) {
    ref.current.type = 'password';
  }
};

interface ShowPasswordButtonProps {
  passwordRef: React.RefObject<HTMLInputElement | null>;
}

const ShowPasswordButton: React.FC<ShowPasswordButtonProps> = ({ passwordRef }) => {
  return (
    <StyledShowPasswordButton onClick={() => togglePasswordVisibility(passwordRef)}>
      <EyeIcon />
    </StyledShowPasswordButton>
  );
};

export default ShowPasswordButton;
