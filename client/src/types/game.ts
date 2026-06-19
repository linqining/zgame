// 游戏相关类型定义

export type RoundStateType =
  | 'waiting'
  | 'shuffling'
  | 'shuffleComplete'
  | 'preFlopReveal'
  | 'preFlop'
  | 'flopReveal'
  | 'flop'
  | 'turnReveal'
  | 'turn'
  | 'riverReveal'
  | 'river'
  | 'showdownReveal'
  | 'showdown'
  | 'handComplete';

export const RoundState = {
  Waiting: 'waiting',
  Shuffling: 'shuffling',
  ShuffleComplete: 'shuffleComplete',
  PreFlopReveal: 'preFlopReveal',
  PreFlop: 'preFlop',
  FlopReveal: 'flopReveal',
  Flop: 'flop',
  TurnReveal: 'turnReveal',
  Turn: 'turn',
  RiverReveal: 'riverReveal',
  River: 'river',
  ShowdownReveal: 'showdownReveal',
  Showdown: 'showdown',
  HandComplete: 'handComplete',
} as const;

export interface Card {
  suit: string;
  rank: string;
}

export interface Player {
  socketId: string;
  pkHex: string;
  name: string;
  chips: number;
  sittingOut: boolean;
}

export interface Seat {
  id: number;
  player: Player | null;
  hand: Card[];
  turn: boolean;
  chips: number;
  bet: number;
  sittingOut: boolean;
  stack: number;
  lastAction: string | null;
}

export interface ShuffleState {
  is_active: boolean;
  current_player_pk: string;
  deck_encrypted: string[][];
  aggregate_pk: string;
  completed_players: string[];
  pending_players: string[];
}

export interface RevealTokenState {
  player_assignments: Record<
    string,
    {
      hand_cards?: Array<{ encrypted_card: string }>;
      community_cards?: Array<{ encrypted_card: string }>;
      hand_card?: Array<{ encrypted_card: string }>;
      community_card?: Array<{ encrypted_card: string }>;
    }
  >;
}

export interface SidePot {
  amount: number;
}

export interface Table {
  id: string;
  /** 链上 Sui Table 对象 ID（如果该表有对应的链上对象） */
  suiTableId?: string;
  seats: Record<number, Seat>;
  roundState: RoundStateType;
  shuffleState: ShuffleState | null;
  revealTokenState: RevealTokenState | null;
  deck?: {
    cards: string[][];
  };
  pot: number;
  currentBet: number;
  minBuyIn: number;
  maxBuyIn: number;
  bigBlind: number;
  smallBlind: number;
  dealerSeatId: number;
  limit: number;
  minBet: number;
  minRaise: number;
  button: number;
  callAmount: number;
  handOver: boolean;
  mainPot: number;
  sidePots: SidePot[];
  players: Player[];
  board: Card[];
  wentToShowdown: boolean;
  winMessages: string[];
}

export interface GameMessage {
  text: string;
  timestamp: number;
}

export interface GameContextType {
  messages: GameMessage[];
  currentTable: Table | null;
  isPlayerSeated: boolean;
  seatId: number | null;
  shuffleLoading: boolean;
  revealLoading: boolean;
  decryptedHandCards: string[];
  communityCards: Card[];
  kickNotification: string | null;
  cryptoEvents: CryptoEvent[];
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
  standUp: () => Promise<void>;
  addMessage: (message: string) => void;
  fold: () => void;
  check: () => void;
  call: () => void;
  raise: (amount: number) => void;
  rebuy: (tableId: string, seatId: number, amount: number) => void;
  sittingOut: () => void;
  sittingIn: () => void;
  expelInitiate: (tableId: string, targetPlayerPk: string) => void;
  clearKickNotification: () => void;
}

// ===== ZK 密码学事件（用于可视化面板） =====
export type CryptoEventType = 'shuffle' | 'remask' | 'reveal_token' | 'leave' | 'reconstruct';

export interface CryptoEvent {
  type: 'crypto_event';
  event_type: CryptoEventType;
  player_pk: string;
  card_index: number | null;
  tx_digest: string | null;
  verified: boolean;
  timestamp: number;
  message?: string;
}
