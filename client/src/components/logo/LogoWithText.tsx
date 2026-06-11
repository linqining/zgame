import React from 'react';
import logoWithTextSvg from '../../assets/img/logo_with_text.svg';
import styled from 'styled-components';

const LogoImage = styled.img`
  display: block;
  height: 50px;
  width: auto;
`;

const LogoWithText: React.FC = () => (
  <LogoImage
    src={logoWithTextSvg}
    alt="Secret Poker"
  />
);

export default LogoWithText;
