import React, { createContext, useContext, useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { darkTheme, isDarkRoute } from '../../styles/themes/darkTheme';
import defaultTheme from '../../styles/theme';

export type ThemeVariant = 'light' | 'dark';

export interface ThemeContextValue {
  variant: ThemeVariant;
  isDark: boolean;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

interface ThemeProviderProps {
  children: React.ReactNode;
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  const location = useLocation();
  const [variant, setVariant] = useState<ThemeVariant>(() =>
    isDarkRoute(location.pathname) ? 'dark' : 'light'
  );

  useEffect(() => {
    const newVariant = isDarkRoute(location.pathname) ? 'dark' : 'light';
    setVariant(newVariant);
  }, [location.pathname]);

  const value: ThemeContextValue = {
    variant,
    isDark: variant === 'dark',
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}

export function useThemeVariant(): ThemeVariant {
  const { variant } = useTheme();
  return variant;
}

export default ThemeContext;
