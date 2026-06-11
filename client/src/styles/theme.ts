import 'styled-components';

interface ThemeColors {
  primaryCta: string;
  primaryCtaDarker: string;
  secondaryCta: string;
  secondaryCtaDarker: string;
  secondaryCtaDarkest: string;
  darkBg: string;
  lightBg: string;
  lightestBg: string;
  fontColorLight: string;
  fontColorDark: string;
  fontColorDarkLighter: string;
  playingCardBg: string;
  playingCardBgLighter: string;
  goldenColorDarker: string;
  goldenColor: string;
  dangerColorLighter: string;
  dangerColor: string;
}

interface ThemeFonts {
  fontFamilySerif: string;
  fontFamilySansSerif: string;
  fontLineHeight: string;
  fontSizeRoot: string;
  fontSizeRootMobile: string;
  fontSizeH1: string;
  fontSizeH2: string;
  fontSizeH3: string;
  fontSizeH4: string;
  fontSizeH5: string;
  fontSizeH6: string;
  fontSizeParagraph: string;
}

interface ThemeOther {
  stdBorderRadius: string;
  cardDropShadow: string;
  navMenuDropShadow: string;
}

export interface Theme {
  colors: ThemeColors;
  fonts: ThemeFonts;
  other: ThemeOther;
}

declare module 'styled-components' {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  export interface DefaultTheme extends Theme {}
}

const theme: Theme = {
  // Colors
  colors: {
    // Primary Brand Colors
    primaryCta: '#4f46e5',
    primaryCtaDarker: '#4338ca',
    secondaryCta: '#667eea',
    secondaryCtaDarker: '#5a67d8',
    secondaryCtaDarkest: '#4f46e5',
    // Secondary Brand Colors
    darkBg: '#e2e8f0',
    lightBg: '#f1f5f9',
    lightestBg: '#ffffff',
    // Font Colors
    fontColorLight: '#f8fafc',
    fontColorDark: '#0f172a',
    fontColorDarkLighter: '#334155',
    // Other colors
    playingCardBg: '#f8fafc',
    playingCardBgLighter: '#ffffff',
    goldenColorDarker: '#d4a843',
    goldenColor: '#e2b84d',
    dangerColorLighter: 'hsl(0, 100%, 56%)',
    dangerColor: 'hsl(0, 100%, 46%)',
  },
  // Fonts
  fonts: {
    // Font Familys
    fontFamilySerif: "'Playfair Display', serif",
    fontFamilySansSerif: "'Roboto', sans-serif",
    // Font Sizes
    fontLineHeight: '1.4',
    fontSizeRoot: '1em',
    fontSizeRootMobile: '0.9em',
    fontSizeH1: 'calc(1.25rem + 4vmin)',
    fontSizeH2: 'calc(1.25rem + 3.5vmin)',
    fontSizeH3: 'calc(1.25rem + 3vmin)',
    fontSizeH4: 'calc(1.25rem + 2vmin)',
    fontSizeH5: 'calc(1.25rem + 1.5vmin)',
    fontSizeH6: 'calc(1.25rem + 1vmin)',
    fontSizeParagraph: '1.2rem',
  },
  // Other styles
  other: {
    // Border-radius
    stdBorderRadius: '2rem',
    // Drop Shadows
    cardDropShadow: '0 8px 30px rgba(0, 0, 0, 0.06)',
    navMenuDropShadow: '-10px 0px 30px rgba(0, 0, 0, 0.06)',
  },
};

export default theme;
