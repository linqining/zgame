import React, { useContext, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Button from '../buttons/Button';
import modalContext from '../../context/modal/modalContext';
import globalContext from '../../context/global/globalContext';
import { ButtonGroup } from '../forms/ButtonGroup';
import { Form } from '../forms/Form';
import { FormGroup } from '../forms/FormGroup';
import { Input } from '../forms/Input';
import gameContext from '../../context/game/gameContext';
import { PositionedUISlot } from './PositionedUISlot';
import { InfoPill } from './InfoPill';
import PokerCard from './PokerCard';
import ChipsAmountPill from './ChipsAmountPill';
import ColoredText from '../typography/ColoredText';
import Text from '../typography/Text';
import PokerChip from '../icons/PokerChip';
import { OccupiedSeat } from './OccupiedSeat';
import { Hand } from './Hand';
import { NameTag } from './NameTag';
import { PlayerName } from './PlayerName';
import contentContext from '../../context/content/contentContext';
import Markdown from 'react-markdown';
import DealerButton from '../icons/DealerButton';
import styled from 'styled-components';
import { Table } from '../../types/game';
import authContext from '../../context/auth/authContext';
import { EmptySeat } from './seatStyles';
import { defaultClient } from '../../sui/config';
import { requestSuiFromFaucetV2, getFaucetHost } from '@mysten/sui/faucet';
import { logger } from '../../helpers/logger';

const StyledSeat = styled.div`
  width: 200px;
  height: 200px;
  display: flex;
  justify-content: center;
  align-items: center;
`;

const BuyinInfo = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
  padding: 0.75rem 1rem;
  background: rgba(77, 162, 255, 0.08);
  border: 1px solid rgba(77, 162, 255, 0.2);
  border-radius: 10px;
  font-size: 0.85rem;
  color: #334155;
`;

const BuyinInfoRow = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;

  img {
    width: 16px;
    height: 16px;
    vertical-align: middle;
    margin-right: 0.25rem;
  }
`;

const ExchangeRate = styled.div`
  font-size: 0.75rem;
  color: #64748b;
  text-align: center;
  padding-top: 0.25rem;
  border-top: 1px dashed rgba(148, 163, 184, 0.3);
`;

// 与 Modal 底部按钮（ModalButton 紫色渐变）保持视觉一致
const ConfirmButton = styled(Button)`
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2) !important;
  color: ${({ theme }) => theme.colors.lightestBg} !important;
  border: none !important;
  border-radius: 10px !important;
  font-weight: 600 !important;
  padding: 0.65rem 2rem !important;
  box-shadow: 0 4px 20px rgba(102, 126, 234, 0.25) !important;
  transition: all 0.35s cubic-bezier(0.22, 1, 0.36, 1) !important;

  &:hover:not(:disabled) {
    box-shadow: 0 6px 24px rgba(102, 126, 234, 0.35) !important;
    transform: translateY(-1px);
  }
`;

// Faucet 按钮：次要样式（描边），与确认/取消按钮区分
const FaucetButton = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  width: 100%;
  padding: 0.55rem 1rem;
  border-radius: 10px;
  border: 1px dashed rgba(77, 162, 255, 0.5);
  background: rgba(77, 162, 255, 0.06);
  color: #4DA2FF;
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;

  img {
    width: 16px;
    height: 16px;
  }

  &:hover:not(:disabled) {
    background: rgba(77, 162, 255, 0.12);
    border-color: rgba(77, 162, 255, 0.8);
  }

  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
`;

interface SeatProps {
  currentTable: Table;
  seatNumber: number;
  isPlayerSeated: boolean;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
}

export const Seat: React.FC<SeatProps> = ({ currentTable, seatNumber, isPlayerSeated, sitDown }) => {
  const { openModal, closeModal } = useContext(modalContext)!;
  const navigate = useNavigate();
  const { chipsAmount } = useContext(globalContext)!;
  const { standUp, seatId, rebuy } = useContext(gameContext)!;
  const { getLocalizedString } = useContext(contentContext)!;
  const { isLoggedIn, walletAddress } = useContext(authContext)!;
  const hasWallet = !!walletAddress;

  // 直接从前端查询 SUI 节点获取钱包余额
  const [suiBalanceMist, setSuiBalanceMist] = useState<number>(0);

  useEffect(() => {
    if (!walletAddress) {
      setSuiBalanceMist(0);
      return;
    }
    let cancelled = false;
    const fetchBalance = async () => {
      try {
        const res = await defaultClient.getBalance({ owner: walletAddress });
        if (!cancelled) {
          setSuiBalanceMist(Number(res.balance.balance) || 0);
        }
      } catch (err) {
        logger.error('[Seat] fetch SUI balance failed:', err);
      }
    };
    fetchBalance();
    // 每 10 秒刷新一次余额
    const interval = setInterval(fetchBalance, 10000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [walletAddress]);

  const seat = currentTable.seats[seatNumber];
  // limit 在链上同步场景可能为 0（链上 BCS 不含此字段），回退到 bigBlind * 100
  const maxBuyin = 5000;
  const minBuyIn = Math.max(currentTable.minBet * 2 * 10, 1000);
  const BUYIN_STEP = 1000;

  // 1 SUI = 10000 chips → 1 chip = 0.0001 SUI
  const CHIPS_PER_SUI = 10000;
  const suiBalanceInSui = suiBalanceMist / 1e9;
  const availableChips = chipsAmount ?? 0;

  // 兑换指定筹码需要的 SUI 数量
  const suiCostForChips = (chips: number): number => chips / CHIPS_PER_SUI;

  // 格式化钱包地址用于显示（前6位...后4位）
  const shortAddress = walletAddress
    ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`
    : '';

  // Faucet 请求状态
  const [faucetLoading, setFaucetLoading] = useState(false);
  const [faucetMsg, setFaucetMsg] = useState<string | null>(null);

  const handleFaucetRequest = async () => {
    if (!walletAddress || faucetLoading) return;
    setFaucetLoading(true);
    setFaucetMsg(null);
    try {
      await requestSuiFromFaucetV2({
        host: getFaucetHost('testnet'),
        recipient: walletAddress,
      });
      setFaucetMsg('领取成功，余额刷新中...');
      // 等待 2 秒后刷新余额
      setTimeout(async () => {
        try {
          const res = await defaultClient.getBalance({ owner: walletAddress });
          setSuiBalanceMist(Number(res.balance.balance) || 0);
          setFaucetMsg(null);
        } catch {
          setFaucetMsg(null);
        }
      }, 2000);
    } catch (err: any) {
      const msg = err?.message || String(err);
      const errMsg = msg.includes('Too many requests') || msg.includes('429')
        ? '请求过于频繁，请稍后再试'
        : `领取失败: ${msg}`;
      setFaucetMsg(errMsg);
      openModal(
        () => <Text textAlign="center">{errMsg}</Text>,
        '领取 SUI 失败',
        '确定',
      );
    } finally {
      setFaucetLoading(false);
    }
  };

  // Debug: log hand cards for the current player's seat
  if (seat && seatId !== null && seat.id === seatId) {
    logger.log('[Seat] seatNumber:', seatNumber, 'seatId:', seatId, 'hand:', seat.hand);
  }

  useEffect(() => {
    if (
      currentTable &&
      isPlayerSeated &&
      seat &&
      seat.id === seatId &&
      seat.stack === 0 &&
      seat.sittingOut
    ) {
      if (availableChips <= minBuyIn || availableChips === 0) {
        standUp().catch(e => logger.error('[Seat] standUp failed:', e));
      } else {
        openModal(
          () => (
            <Form
              onSubmit={(e) => {
                e.preventDefault();

                const amount = +(document.getElementById('amount') as HTMLInputElement).value;

                if (
                  amount &&
                  amount >= minBuyIn &&
                  amount % BUYIN_STEP === 0 &&
                  amount <= availableChips &&
                  amount <= maxBuyin
                ) {
                  rebuy(currentTable.id, seatNumber, parseInt(String(amount)));
                  closeModal();
                }
              }}
            >
              <BuyinInfo>
                <BuyinInfoRow>
                  <span>钱包地址</span>
                  <strong>{shortAddress || '-'}</strong>
                </BuyinInfoRow>
                <BuyinInfoRow>
                  <span><img src="/sui-sui-logo.svg" alt="SUI" />SUI 余额</span>
                  <strong>{suiBalanceInSui.toLocaleString(undefined, { maximumFractionDigits: 4 })} SUI</strong>
                </BuyinInfoRow>
                <BuyinInfoRow>
                  <span>可兑换筹码</span>
                  <strong>{availableChips.toLocaleString()}</strong>
                </BuyinInfoRow>
                <BuyinInfoRow>
                  <span>本次兑换花费</span>
                  <strong>{suiCostForChips(minBuyIn).toLocaleString(undefined, { maximumFractionDigits: 4 })} SUI</strong>
                </BuyinInfoRow>
                <ExchangeRate>汇率: 1 SUI = {CHIPS_PER_SUI.toLocaleString()} 筹码</ExchangeRate>
              </BuyinInfo>
              <FormGroup>
                <Input
                  id="amount"
                  type="number"
                  min={minBuyIn}
                  max={availableChips <= maxBuyin ? availableChips : maxBuyin}
                  step={BUYIN_STEP}
                  defaultValue={minBuyIn}
                />
              </FormGroup>
              <ButtonGroup>
                <ConfirmButton primary type="submit" fullWidth>
                  {getLocalizedString('game_rebuy-modal_confirm')}
                </ConfirmButton>
                <FaucetButton
                  type="button"
                  onClick={handleFaucetRequest}
                  disabled={faucetLoading || !walletAddress}
                >
                  <img src="/sui-sui-logo.svg" alt="SUI" />
                  {faucetLoading ? '领取中...' : '领取测试 SUI (Faucet)'}
                </FaucetButton>
                {faucetMsg && (
                  <Text textAlign="center" style={{ fontSize: '0.8rem', color: '#64748b' }}>
                    {faucetMsg}
                  </Text>
                )}
              </ButtonGroup>
            </Form>
          ),
          getLocalizedString('game_rebuy-modal_header'),
          getLocalizedString('game_rebuy-modal_cancel'),
          () => {
            standUp().catch(e => logger.error('[Seat] standUp failed:', e));
            closeModal();
          },
          () => {
            standUp().catch(e => logger.error('[Seat] standUp failed:', e));
            closeModal();
          },
        );
      }
    }
    // eslint-disable-next-line
  }, [currentTable]);

  return (
    <StyledSeat>
      <AnimatePresence mode="wait">
        {!seat ? (
          <motion.div
            key="empty"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
            style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
            }}
          >
            {!isPlayerSeated ? (
              <Button
                small
                onClick={() => {
                  if (!isLoggedIn && !hasWallet) {
                    openModal(
                      () => <Text textAlign="center">{getLocalizedString('game_login-required_text')}</Text>,
                      getLocalizedString('login_page-header_txt'),
                      getLocalizedString('navbar-login_btn'),
                      () => {
                        closeModal();
                        navigate('/', { state: { showLogin: true } });
                      },
                    );
                    return;
                  }
                  openModal(
                    () => (
                      <Form
                        onSubmit={(e) => {
                          e.preventDefault();

                          const amount = +(document.getElementById('amount') as HTMLInputElement).value;

                          if (
                            amount &&
                            amount >= minBuyIn &&
                            amount % BUYIN_STEP === 0 &&
                            amount <= availableChips &&
                            amount <= maxBuyin
                          ) {
                            sitDown(
                              currentTable.id,
                              seatNumber,
                              parseInt(String(amount)),
                            );
                            closeModal();
                          }
                        }}
                      >
                        <BuyinInfo>
                          <BuyinInfoRow>
                            <span>钱包地址</span>
                            <strong>{shortAddress || '-'}</strong>
                          </BuyinInfoRow>
                          <BuyinInfoRow>
                            <span><img src="/sui-sui-logo.svg" alt="SUI" />SUI 余额</span>
                            <strong>{suiBalanceInSui.toLocaleString(undefined, { maximumFractionDigits: 4 })} SUI</strong>
                          </BuyinInfoRow>
                          <BuyinInfoRow>
                            <span>可兑换筹码</span>
                            <strong>{availableChips.toLocaleString()}</strong>
                          </BuyinInfoRow>
                          <BuyinInfoRow>
                            <span>本次兑换花费</span>
                            <strong>{suiCostForChips(minBuyIn).toLocaleString(undefined, { maximumFractionDigits: 4 })} SUI</strong>
                          </BuyinInfoRow>
                          <ExchangeRate>汇率: 1 SUI = {CHIPS_PER_SUI.toLocaleString()} 筹码</ExchangeRate>
                        </BuyinInfo>
                        <FormGroup>
                          <Input
                            id="amount"
                            type="number"
                            min={minBuyIn}
                            max={availableChips <= maxBuyin ? availableChips : maxBuyin}
                            defaultValue={minBuyIn}
                          />
                        </FormGroup>
                        <ButtonGroup>
                          <ConfirmButton primary type="submit" fullWidth>
                            {getLocalizedString('game_buyin-modal_confirm')}
                          </ConfirmButton>
                          <FaucetButton
                            type="button"
                            onClick={handleFaucetRequest}
                            disabled={faucetLoading || !walletAddress}
                          >
                            <img src="/sui-sui-logo.svg" alt="SUI" />
                            {faucetLoading ? '领取中...' : '领取测试 SUI (Faucet)'}
                          </FaucetButton>
                          {faucetMsg && (
                            <Text textAlign="center" style={{ fontSize: '0.8rem', color: '#64748b' }}>
                              {faucetMsg}
                            </Text>
                          )}
                        </ButtonGroup>
                      </Form>
                    ),
                    getLocalizedString('game_buyin-modal_header'),
                    getLocalizedString('game_buyin-modal_cancel'),
                  );
                }}
              >
                {getLocalizedString('game_sitdown-btn')}
              </Button>
            ) : (
              <EmptySeat>
                <Markdown>{getLocalizedString('game_table_empty-seat')}</Markdown>
              </EmptySeat>
            )}
          </motion.div>
        ) : (
          <motion.div
            key="occupied"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{
              opacity: 1,
              scale: 1,
              transition: { duration: 0.3, ease: 'easeOut' },
            }}
            exit={{ opacity: 0, transition: { duration: 0.3, ease: 'easeIn' } }}
            style={{
              position: 'absolute',
              display: 'flex',
              textAlign: 'center',
              justifyContent: 'center',
              alignItems: 'center',
              transformOrigin: 'center center',
              backfaceVisibility: 'hidden',
              WebkitBackfaceVisibility: 'hidden',
            }}
          >
            <PositionedUISlot top="-6.25rem" left="-75px" origin="top center">
              <NameTag>
                <ColoredText primary textAlign="center">
                  <PlayerName name={seat.player!.name} />
                  <br />
                  {seat.stack && (
                    <ColoredText secondary>
                      <PokerChip width="15" height="15" />{' '}
                      {new Intl.NumberFormat(
                        document.documentElement.lang,
                      ).format(seat.stack)}
                    </ColoredText>
                  )}
                </ColoredText>
              </NameTag>
            </PositionedUISlot>
            <PositionedUISlot>
              <OccupiedSeat seatNumber={seatNumber} hasTurn={seat.turn} />
            </PositionedUISlot>
            <PositionedUISlot
              left="4vh"
              style={{
                display: 'flex',
                textAlign: 'center',
                justifyContent: 'center',
                alignItems: 'center',
              }}
              origin="center right"
            >
              <Hand>
                {seat.hand &&
                  seat.hand.map((card, index) => (
                    <PokerCard
                      key={index}
                      card={card}
                      width="5vw"
                      maxWidth="60px"
                      minWidth="30px"
                    />
                  ))}
              </Hand>
            </PositionedUISlot>

            {currentTable.button === seatNumber && (
              <PositionedUISlot
                right="35px"
                origin="center left"
                style={{ zIndex: '55' }}
              >
                <DealerButton />
              </PositionedUISlot>
            )}

            <PositionedUISlot
              top="6vh"
              style={{ minWidth: '150px', zIndex: '55' }}
              origin="bottom center"
            >
              <ChipsAmountPill chipsAmount={seat.bet} />
              {!currentTable.handOver && seat.lastAction && (
                <InfoPill>{seat.lastAction}</InfoPill>
              )}
            </PositionedUISlot>
          </motion.div>
        )}
      </AnimatePresence>
    </StyledSeat>
  );
};
