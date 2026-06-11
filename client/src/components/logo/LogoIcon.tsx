import React from 'react';
import logoSvg from '../../assets/img/logo-icon-transparent.svg';

interface LogoIconProps {
  color?: string;
  size?: number;
}

const LogoIcon: React.FC<LogoIconProps> = ({ size = 40 }) => (
  <img
    src={logoSvg}
    alt="Secret Poker"
    width={size}
    height={size}
    style={{ display: 'block' }}
  />
);

export default LogoIcon;
