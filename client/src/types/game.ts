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
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string) => void;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
  standUp: () => void;
  addMessage: (message: string) => void;
  fold: () => void;
  check: () => void;
  call: () => void;
  raise: (amount: number) => void;
  rebuy: (tableId: string, seatId: number, amount: number) => void;
  sittingOut: () => void;
  sittingIn: () => void;
  expelInitiate: (tableId: string, targetPlayerPk: string) => void;
}
