import styled, { css } from 'styled-components';

interface ButtonProps {
  primary?: boolean;
  secondary?: boolean;
  dark?: boolean;
  darkSecondary?: boolean;
  small?: boolean;
  large?: boolean;
  fullWidth?: boolean;
  fullWidthOnMobile?: boolean;
  to?: string;
  autoFocus?: boolean;
}

const Button = styled.button.withConfig({
  shouldForwardProp: (prop) => !['primary', 'secondary', 'dark', 'darkSecondary', 'small', 'large', 'fullWidth', 'fullWidthOnMobile'].includes(prop),
})<ButtonProps>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 0.75rem 1.5rem;
  outline: none;
  border: 2px solid rgba(0, 0, 0, 0);
  border-radius: ${({ theme }) => theme.other.stdBorderRadius};
  background-color: ${({ theme }) => theme.colors.goldenColor};
  color: ${({ theme }) => theme.colors.fontColorDark};
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-weight: 400;
  font-size: 1.3rem;
  line-height: 1.3rem;
  min-width: 150px;
  cursor: pointer;
  transition: all 0.3s;

  &:visited {
    background-color: ${({ theme }) => theme.colors.goldenColorDarker};
    color: ${({ theme }) => theme.colors.fontColorDark};
  }

  &:hover,
  &:active {
    background-color: ${({ theme }) => theme.colors.goldenColorDarker};
    color: ${({ theme }) => theme.colors.fontColorDark};
  }

  &:focus {
    outline: none;
    border: 2px solid ${({ theme }) => theme.colors.primaryCtaDarker};
    color: ${({ theme }) => theme.colors.fontColorDark};
  }

  &:disabled {
    background-color: grey;
    border-color: 2px solid grey;
  }

  ${({ primary, large, small }) =>
    primary &&
    css`
      color: ${({ theme }) => theme.colors.primaryCta};
      padding: ${() => {
        if (large) return 'calc(1rem - 2px) calc(2rem - 2px)';
        else if (small) return 'calc(0.5rem - 2px) calc(1rem - 2px)';
        else return 'calc(0.75rem - 2px) calc(1.5rem - 2px)';
      }};

      &,
      &:visited {
        background-color: ${({ theme }) => theme.colors.primaryCta};
        color: ${({ theme }) => theme.colors.fontColorLight};
      }

      &:hover,
      &:active {
        background-color: ${({ theme }) => theme.colors.primaryCtaDarker};
        border-color: ${({ theme }) => theme.colors.primaryCtaDarker};
        color: ${({ theme }) => theme.colors.fontColorLight};
      }

      &:focus {
        color: ${({ theme }) => theme.colors.fontColorLight};
      }

      &:disabled {
        background-color: grey;
        border-color: grey;
        color: ${({ theme }) => theme.colors.fontColorDark};
      }
    `}

  ${({ secondary }) =>
    secondary &&
    css`
      color: ${({ theme }) => theme.colors.primaryCta};

      &,
      &:visited {
        border: 2px solid ${({ theme }) => theme.colors.primaryCta};
        background-color: transparent;
        color: ${({ theme }) => theme.colors.primaryCta};
      }

      &:hover,
      &:active {
        border: 2px solid ${({ theme }) => theme.colors.primaryCtaDarker};
        background-color: transparent;
        color: ${({ theme }) => theme.colors.primaryCtaDarker};
      }

      &:focus {
        outline: none;
        border: 2px solid ${({ theme }) => theme.colors.primaryCtaDarker};
        color: ${({ theme }) => theme.colors.primaryCtaDarker};
      }

      &:disabled {
        border: 2px solid grey;
        background-color: grey;
        color: ${({ theme }) => theme.colors.fontColorDark};
      }
    `}

  ${({ dark, large, small }) =>
    dark &&
    css`
      /* TODO: #764ba2 提取到 theme */
      background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2);
      color: ${({ theme }) => theme.colors.lightestBg};
      border: none;
      box-shadow: 0 4px 20px rgba(102, 126, 234, 0.35);
      padding: ${() => {
        if (large) return 'calc(1rem - 2px) calc(2rem - 2px)';
        else if (small) return 'calc(0.5rem - 2px) calc(1rem - 2px)';
        else return 'calc(0.75rem - 2px) calc(1.5rem - 2px)';
      }};

      &,
      &:visited {
        /* TODO: #764ba2 提取到 theme */
        background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2);
        color: ${({ theme }) => theme.colors.lightestBg};
      }

      &:hover,
      &:active {
        background: linear-gradient(135deg, #7b8ff0, #8559ad);
        transform: translateY(-2px);
        box-shadow: 0 12px 35px rgba(102, 126, 234, 0.55);
        color: ${({ theme }) => theme.colors.lightestBg};
      }

      &:focus {
        outline: none;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.3);
        color: ${({ theme }) => theme.colors.lightestBg};
      }

      &:disabled {
        background: grey;
        box-shadow: none;
        color: ${({ theme }) => theme.colors.lightestBg};
      }
    `}

  ${({ darkSecondary, large, small }) =>
    darkSecondary &&
    css`
      background: rgba(241, 245, 249, 0.8);
      color: ${({ theme }) => theme.colors.fontColorDark};
      border: 1px solid rgba(203, 213, 225, 0.8);
      backdrop-filter: blur(10px);
      padding: ${() => {
        if (large) return 'calc(1rem - 2px) calc(2rem - 2px)';
        else if (small) return 'calc(0.5rem - 2px) calc(1rem - 2px)';
        else return 'calc(0.75rem - 2px) calc(1.5rem - 2px)';
      }};

      &,
      &:visited {
        background: rgba(241, 245, 249, 0.8);
        color: ${({ theme }) => theme.colors.fontColorDark};
        border-color: rgba(203, 213, 225, 0.8);
      }

      &:hover,
      &:active {
        background: rgba(226, 232, 240, 0.9);
        border-color: #3b82f6;
        color: ${({ theme }) => theme.colors.fontColorDark};
        transform: translateY(-2px);
      }

      &:focus {
        outline: none;
        border-color: ${({ theme }) => theme.colors.secondaryCta};
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
        color: ${({ theme }) => theme.colors.fontColorDark};
      }

      &:disabled {
        background: grey;
        border-color: grey;
        color: ${({ theme }) => theme.colors.lightestBg};
      }
    `}

  ${({ large }) =>
    large &&
    css`
      font-size: 1.6rem;
      line-height: 1.6rem;
      min-width: 250px;
      padding: 1rem 2rem;
    `}

  ${({ small }) =>
    small &&
    css`
      font-size: 1.1rem;
      line-height: 1.1rem;
      min-width: 125px;
      padding: 0.5rem 1rem;
    `}

  ${({ fullWidth }) =>
    fullWidth &&
    css`
      width: 100%;
    `}

    @media screen and (max-width: 1024px) {
    ${({ large }) =>
      large &&
      css`
        font-size: 1.4rem;
        line-height: 1.4rem;
        min-width: 250px;
        padding: 0.75rem 1.5rem;
      `}

    ${({ fullWidthOnMobile, fullWidth }) =>
      (fullWidthOnMobile || fullWidth) &&
      css`
        width: 100%;
      `}
  }
`;

export default Button;
