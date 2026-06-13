import React, { useContext, useEffect, useState, useRef } from 'react';
import Container from '../components/layout/Container';
import Button from '../components/buttons/Button';
import gameContext from '../context/game/gameContext';
import socketContext from '../context/websocket/socketContext';
import PokerTable from '../components/game/PokerTable';
import { RotateDevicePrompt } from '../components/game/RotateDevicePrompt';
import { PositionedUISlot } from '../components/game/PositionedUISlot';
import { PokerTableWrapper } from '../components/game/PokerTableWrapper';
import { Seat } from '../components/game/Seat';
import Text from '../components/typography/Text';
import { useModalContext } from '../context/modal/modalContext';
import { useNavigate } from 'react-router-dom';
import { TableInfoWrapper } from '../components/game/TableInfoWrapper';
import { InfoPill } from '../components/game/InfoPill';
import { GameUI } from '../components/game/GameUI';
import { GameStateInfo } from '../components/game/GameStateInfo';
import PokerCard from '../components/game/PokerCard';
import { useContentContext } from '../context/content/contentContext';
import { PlayerContext } from '../context/player/PlayerContext';
import Loader from '../components/loading/Loader';
import { FETCH_LOBBY_INFO } from '../pokergame/actions';

const Play: React.FC = () => {
  const navigate = useNavigate();
  const { socket, isConnected } = useContext(socketContext)!;
  const { openModal } = useModalContext();
  const {
    messages,
    currentTable,
    isPlayerSeated,
    seatId,
    joinTable,
    leaveTable,
    sitDown,
    standUp,
    fold,
    check,
    call,
    raise,
  } = useContext(gameContext)!;
  const { getLocalizedString } = useContentContext();
  const { pkHex } = useContext(PlayerContext)!;

  const [bet, setBet] = useState(0);
  const [hasJoined, setHasJoined] = useState(false);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const reconnectAttemptRef = useRef(0);
  const hasShownLostModalRef = useRef(false);
  const isUnmountingRef = useRef(false);

  useEffect(() => {
    return () => {
      isUnmountingRef.current = true;
    };
  }, []);

  useEffect(() => {
    if (!socket) return;

    joinTable(1, pkHex || '');
    setHasJoined(true);

    return () => {
      if (isUnmountingRef.current) {
        leaveTable(false, pkHex || undefined);
      }
      setHasJoined(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [socket]);

  // Handle reconnection when connection is lost after joining
  useEffect(() => {
    if (!hasJoined) return;

    if (isConnected) {
      // Connection restored
      setIsReconnecting(false);
      reconnectAttemptRef.current = 0;
      hasShownLostModalRef.current = false;
      return;
    }

    // Connection lost - attempt manual reconnect via FETCH_LOBBY_INFO
    if (socket && !isConnected && !isReconnecting && !hasShownLostModalRef.current) {
      setIsReconnecting(true);
      reconnectAttemptRef.current += 1;

      const token = localStorage.token;
      if (token) {
        console.log(`[Reconnect] Attempt ${reconnectAttemptRef.current}, emitting FETCH_LOBBY_INFO`);
        socket.emit(FETCH_LOBBY_INFO, token);
      }
    }

    // If socket is completely gone (not just disconnected), show lost modal
    if (!socket && !hasShownLostModalRef.current) {
      hasShownLostModalRef.current = true;
      openModal(
        () => (
          <Text>{getLocalizedString('game_lost-connection-modal_text')}</Text>
        ),
        getLocalizedString('game_lost-connection-modal_header'),
        getLocalizedString('game_lost-connection-modal_btn-txt'),
        () => navigate('/'),
      );
    }
  }, [hasJoined, isConnected, socket, isReconnecting, openModal, navigate, getLocalizedString]);

  useEffect(() => {
    if (currentTable && seatId != null && currentTable.seats && currentTable.seats[seatId]) {
      const seatBet = currentTable.seats[seatId].bet || 0;
      const currentBet = currentTable.currentBet || 0;
      setBet(Math.max(currentBet - seatBet, 0));
    }
  }, [currentTable, seatId]);

  // Waiting for socket connection
  if (!socket) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
        <Text textAlign="center" style={{ marginTop: '1rem' }}>
          Connecting...
        </Text>
      </Container>
    );
  }

  // Socket exists but disconnected - show reconnecting overlay
  if (!isConnected) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
        <Text textAlign="center" style={{ marginTop: '1rem' }}>
          Reconnecting...
        </Text>
      </Container>
    );
  }

  return (
    <>
      <RotateDevicePrompt />
      <Container fullHeight>
        {currentTable && (
          <>
            <PositionedUISlot
              bottom="2vh"
              left="1.5rem"
              scale="0.65"
              style={{ zIndex: '50' }}
            >
              <Button small secondary onClick={() => leaveTable(true, pkHex || undefined)}>
                {getLocalizedString('game_leave-table-btn')}
              </Button>
            </PositionedUISlot>
            {!isPlayerSeated && (
              <PositionedUISlot
                bottom="1.5vh"
                right="1.5rem"
                scale="0.65"
                style={{ pointerEvents: 'none', zIndex: '50' }}
                origin="bottom right"
              >
                <TableInfoWrapper>
                  <Text textAlign="right">
                    <strong>{currentTable.id}</strong> |{' '}
                    <strong>
                      {getLocalizedString('game_info_limit-lbl')}:{' '}
                    </strong>
                    {new Intl.NumberFormat(
                      document.documentElement.lang,
                    ).format(currentTable.minBuyIn)}{' '}
                    |{' '}
                    <strong>
                      {getLocalizedString('game_info_blinds-lbl')}:{' '}
                    </strong>
                    {new Intl.NumberFormat(
                      document.documentElement.lang,
                    ).format(currentTable.smallBlind)}{' '}
                    /{' '}
                    {new Intl.NumberFormat(
                      document.documentElement.lang,
                    ).format(currentTable.bigBlind)}
                  </Text>
                </TableInfoWrapper>
              </PositionedUISlot>
            )}
          </>
        )}
        <PokerTableWrapper>
          <PokerTable />
          {currentTable && (
            <>
              <PositionedUISlot
                top="-5%"
                left="0"
                scale="0.55"
                origin="top left"
              >
                <Seat
                  seatNumber={1}
                  currentTable={currentTable}
                  isPlayerSeated={isPlayerSeated}
                  sitDown={sitDown}
                />
              </PositionedUISlot>
              <PositionedUISlot top="-5%" scale="0.55" origin="top center">
                <Seat
                  seatNumber={2}
                  currentTable={currentTable}
                  isPlayerSeated={isPlayerSeated}
                  sitDown={sitDown}
                />
              </PositionedUISlot>
              <PositionedUISlot
                top="-5%"
                right="2%"
                scale="0.55"
                origin="top right"
              >
                <Seat
                  seatNumber={3}
                  currentTable={currentTable}
                  isPlayerSeated={isPlayerSeated}
                  sitDown={sitDown}
                />
              </PositionedUISlot>
              <PositionedUISlot
                bottom="15%"
                right="2%"
                scale="0.55"
                origin="bottom right"
              >
                <Seat
                  seatNumber={4}
                  currentTable={currentTable}
                  isPlayerSeated={isPlayerSeated}
                  sitDown={sitDown}
                />
              </PositionedUISlot>
              <PositionedUISlot
                bottom="15%"
                left="0"
                scale="0.55"
                origin="bottom left"
              >
                <Seat
                  seatNumber={5}
                  currentTable={currentTable}
                  isPlayerSeated={isPlayerSeated}
                  sitDown={sitDown}
                />
              </PositionedUISlot>
              <PositionedUISlot
                width="100%"
                origin="center center"
                scale="0.60"
                style={{
                  display: 'flex',
                  textAlign: 'center',
                  justifyContent: 'center',
                  alignItems: 'center',
                }}
              >
                {currentTable.board && currentTable.board.length > 0 && (
                  <>
                    {currentTable.board.map((card, index) => (
                      <PokerCard key={index} card={card} />
                    ))}
                  </>
                )}
              </PositionedUISlot>
              <PositionedUISlot bottom="8%" scale="0.60" origin="bottom center">
                {messages && messages.length > 0 && (
                  <>
                    <InfoPill>{messages[messages.length - 1].text}</InfoPill>
                    {!isPlayerSeated && (
                      <InfoPill>{getLocalizedString('game_sitdown-prompt')}</InfoPill>
                    )}
                    {currentTable.winMessages && currentTable.winMessages.length > 0 && (
                      <InfoPill>
                        {currentTable.winMessages[currentTable.winMessages.length - 1]}
                      </InfoPill>
                    )}
                  </>
                )}
              </PositionedUISlot>
              <PositionedUISlot
                bottom="25%"
                scale="0.60"
                origin="center center"
              >
                {(!currentTable.winMessages || currentTable.winMessages.length === 0) && (
                  <GameStateInfo currentTable={currentTable} />
                )}
              </PositionedUISlot>
            </>
          )}
        </PokerTableWrapper>

        {currentTable &&
          isPlayerSeated &&
          seatId != null &&
          currentTable.seats[seatId] &&
          currentTable.seats[seatId].turn && (
            <GameUI
              currentTable={currentTable}
              seatId={seatId}
              bet={bet}
              setBet={setBet}
              raise={raise}
              standUp={standUp}
              fold={fold}
              check={check}
              call={call}
            />
          )}
      </Container>
    </>
  );
};

export default Play;
