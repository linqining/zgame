import styled, { css } from 'styled-components';

interface ButtonProps {
  primary?: boolean;
  secondary?: boolean;
  small?: boolean;
  large?: boolean;
  fullWidth?: boolean;
  fullWidthOnMobile?: boolean;
  to?: string;
  autoFocus?: boolean;
}

const Button = styled.button.withConfig({
  shouldForwardProp: (prop) => !['primary', 'secondary', 'small', 'large', 'fullWidth', 'fullWidthOnMobile'].includes(prop),
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
