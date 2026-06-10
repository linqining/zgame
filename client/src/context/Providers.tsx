import React from 'react';
import GlobalState from './global/GlobalState';
import AuthProvider from './auth/AuthProvider';
import LocaProvider from './localization/LocaProvider';
import ContentProvider from './content/ContentProvider';
import ModalProvider from './modal/ModalProvider';
import { ThemeProvider } from 'styled-components';
import theme from '../styles/theme';
import Normalize from '../styles/Normalize';
import GlobalStyles from '../styles/Global';
import { BrowserRouter } from 'react-router-dom';
import OfflineProvider from './offline/OfflineProvider';
import WebSocketProvider from './websocket/WebsocketProvider';
import PlayerProvider from './player/PlayerContext';
import GameState from './game/GameState';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { DAppKitProvider } from '@mysten/dapp-kit-react';
import { dAppKit } from '../sui/config';

const queryClient = new QueryClient();

interface ProvidersProps {
  children: React.ReactNode;
}

const Providers: React.FC<ProvidersProps> = ({ children }) => (
  <BrowserRouter future={{ v7_relativeSplatPath: true, v7_startTransition: true }}>
    <QueryClientProvider client={queryClient}>
      <DAppKitProvider dAppKit={dAppKit}>
        <ThemeProvider theme={theme}>
          <GlobalState>
            <LocaProvider>
              <ContentProvider>
                <AuthProvider>
                  <ModalProvider>
                    <OfflineProvider>
                      <WebSocketProvider>
                        <PlayerProvider>
                          <GameState>
                            <Normalize />
                            <GlobalStyles />
                            {children}
                          </GameState>
                        </PlayerProvider>
                      </WebSocketProvider>
                    </OfflineProvider>
                  </ModalProvider>
                </AuthProvider>
              </ContentProvider>
            </LocaProvider>
          </GlobalState>
        </ThemeProvider>
      </DAppKitProvider>
    </QueryClientProvider>
  </BrowserRouter>
);

export default Providers;
