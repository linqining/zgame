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
import { getToken } from '../helpers/getToken';
// ZK 密码学事件可视化（紧凑版）
import CryptoEventStream from '../components/crypto/CryptoEventStream';
import NarrationOverlay from '../components/crypto/NarrationOverlay';
import { Shield, ChevronDown, ChevronUp } from 'lucide-react';

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
    kickNotification,
    clearKickNotification,
    cryptoEvents,
  } = useContext(gameContext)!;
  const { getLocalizedString } = useContentContext();
  const { pkHex } = useContext(PlayerContext)!;

  const [bet, setBet] = useState(0);
  const [hasJoined, setHasJoined] = useState(false);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [isLeaving, setIsLeaving] = useState(false);
  const reconnectAttemptRef = useRef(0);
  const hasShownLostModalRef = useRef(false);
  const isUnmountingRef = useRef(false);
  // 重试计数器：进入 /play 后若 currentTable 一直为空，则重试 FETCH_LOBBY_INFO + joinTable
  const joinRetryRef = useRef(0);
  const MAX_JOIN_RETRIES = 3;
  // 用 ref 在 join effect 中读取最新的 currentTable，避免将其加入依赖数组导致频繁重跑
  const currentTableRef = useRef(currentTable);
  // ZK 密码学事件面板开关（默认收起，避免遮挡牌桌核心区域）
  const [showCryptoPanel, setShowCryptoPanel] = useState(false);

  useEffect(() => {
    currentTableRef.current = currentTable;
  }, [currentTable]);

  useEffect(() => {
    return () => {
      isUnmountingRef.current = true;
    };
  }, []);

  useEffect(() => {
    // 等待 socket 连接建立后再 joinTable。
    if (!socket || !isConnected) return;

    // 如果 currentTable 已经存在（例如从别的页面返回 /play，GameState 仍持有 table 状态），
    // 直接跳过 joinTable 和 FETCH_LOBBY_INFO，避免每次进入都卡一下等 lobby 信息。
    if (currentTableRef.current) {
      setHasJoined(true);
      return;
    }

    // 重置重试计数器
    joinRetryRef.current = 0;

    // 快速路径：WebSocketProvider 在 socket connect 时已 emit 过 FETCH_LOBBY_INFO，
    // 服务器通常已注册当前玩家，直接 joinTable 即可拿到 TABLE_UPDATED。
    // 若因竞态导致 joinTable 失败（currentTable 仍为空），由下方重试 effect 补发 FETCH_LOBBY_INFO。
    joinTable(1, pkHex || '');
    setHasJoined(true);

    return () => {
      // 仅在组件真正卸载时 leaveTable，断线重连场景不触发
      if (isUnmountingRef.current) {
        // 组件卸载时不需要等待完成，直接触发即可
        leaveTable(false, pkHex || undefined, true);
        setHasJoined(false);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [socket, isConnected]);

  // 重试机制：joinTable 后若 currentTable 仍为空，则重试 FETCH_LOBBY_INFO + joinTable。
  // 解决因服务器端 FETCH_LOBBY_INFO 与 JOIN_TABLE 并发处理导致的竞态问题。
  useEffect(() => {
    if (!hasJoined || !socket || !isConnected || currentTable) return;
    if (joinRetryRef.current >= MAX_JOIN_RETRIES) return;

    const timer = setTimeout(() => {
      joinRetryRef.current += 1;
      console.log(`[Play] currentTable still null, retry ${joinRetryRef.current}/${MAX_JOIN_RETRIES}`);
      // 重试时才补发 FETCH_LOBBY_INFO，确保服务器注册了当前玩家
      const token = getToken();
      if (token) {
        socket.emit(FETCH_LOBBY_INFO, token);
      }
      joinTable(1, pkHex || '');
    }, 1000);

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasJoined, socket, isConnected, currentTable]);

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

      const token = getToken();
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

  // Auto-dismiss kick notification after 5 seconds
  useEffect(() => {
    if (kickNotification) {
      const timer = setTimeout(() => {
        clearKickNotification();
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [kickNotification, clearKickNotification]);

  // Waiting for socket connection
  if (!socket) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
        <Text textAlign="center" style={{ marginTop: '1rem' }}>
          {getLocalizedString('play_connecting')}
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
          {getLocalizedString('play_reconnecting')}
        </Text>
      </Container>
    );
  }

  return (
    <>
      {isLeaving && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15, 23, 42, 0.7)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 9999,
          }}
        >
          <Loader />
          <Text textAlign="center" style={{ marginTop: '1rem', color: '#fff' }}>
            {getLocalizedString('play_leaving') || '正在离开牌桌...'}
          </Text>
        </div>
      )}
      {kickNotification && (
        <div
          onClick={clearKickNotification}
          style={{
            position: 'fixed',
            top: '1.5rem',
            left: '50%',
            transform: 'translateX(-50%)',
            background: 'rgba(239, 68, 68, 0.95)',
            color: '#fff',
            padding: '0.8rem 1.5rem',
            borderRadius: '10px',
            fontSize: '0.95rem',
            fontWeight: 600,
            zIndex: 1000,
            cursor: 'pointer',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
            maxWidth: '90vw',
            textAlign: 'center',
          }}
        >
          {kickNotification}
        </div>
      )}
      {/* ZK 密码学事件浮动面板（可收起，位于右上角，不遮挡牌桌核心区域） */}
      <div
        style={{
          position: 'fixed',
          top: '1rem',
          right: '1rem',
          zIndex: 900,
          maxWidth: '320px',
          width: 'calc(100vw - 2rem)',
          pointerEvents: 'auto',
        }}
      >
        {/* 折叠/展开切换按钮 */}
        <button
          onClick={() => setShowCryptoPanel((v) => !v)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            width: '100%',
            justifyContent: 'space-between',
            background: showCryptoPanel
              ? 'rgba(15, 23, 42, 0.92)'
              : 'rgba(59, 130, 246, 0.92)',
            color: '#fff',
            border: 'none',
            borderRadius: showCryptoPanel ? '8px 8px 0 0' : '8px',
            padding: '0.45rem 0.7rem',
            fontSize: '0.72rem',
            fontWeight: 700,
            cursor: 'pointer',
            boxShadow: '0 2px 8px rgba(0, 0, 0, 0.2)',
            fontFamily: "'JetBrains Mono', monospace",
          }}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Shield size={13} />
            {getLocalizedString('play_zk-crypto-events')}
            {cryptoEvents.length > 0 && (
              <span
                style={{
                  background: 'rgba(255, 255, 255, 0.25)',
                  borderRadius: 10,
                  padding: '0 0.4rem',
                  fontSize: '0.62rem',
                }}
              >
                {cryptoEvents.length}
              </span>
            )}
          </span>
          {showCryptoPanel ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </button>

        {/* 展开后的面板内容 */}
        {showCryptoPanel && (
          <div
            style={{
              background: 'rgba(255, 255, 255, 0.97)',
              borderRadius: '0 0 8px 8px',
              padding: '0.5rem',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
              maxHeight: '40vh',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.4rem',
            }}
          >
            {/* 当前阶段叙事（一行简短文案） */}
            {currentTable && (
              <NarrationOverlay
                phase={currentTable.roundState}
                cryptoEventCount={cryptoEvents.length}
              />
            )}
            {/* 紧凑版密码学事件流 */}
            <CryptoEventStream
              events={cryptoEvents}
              compact
              compactMaxItems={6}
            />
          </div>
        )}
      </div>
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
              <Button small secondary onClick={async () => {
                if (isLeaving) return;
                setIsLeaving(true);
                try {
                  await leaveTable(true, pkHex || undefined);
                } catch (e) {
                  console.error('[Play] leaveTable failed:', e);
                  setIsLeaving(false);
                }
              }} disabled={isLeaving}>
                {isLeaving ? getLocalizedString('play_leaving') || '离开中...' : getLocalizedString('game_leave-table-btn')}
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
