// API 请求/响应类型

import { AxiosResponse } from 'axios';
import { Card, Table } from './game';

export interface JoinGameRequest {
  pk_hex: string;
  pk_proof: string;
}

export interface JoinGameResponse {
  gameId: string;
}

export interface ShuffleRequest {
  pk_hex: string;
  output_cards: string[][];
  shuffle_proof: string;
}

export interface JoinAndShuffleRequest {
  pk_hex: string;
  pk_proof: string;
  mask_and_shuffle_round: {
    mask_cards: string[][];
    output_cards: string[][];
    remask_proof: string;
    shuffle_proof: string;
  };
}

export interface PlayerActionRequest {
  action: string;
  amount?: number;
}

export interface RevealTokenRequest {
  pk_hex: string;
  reveal_tokens: string[];
}

export interface AuthWalletRequest {
  address: string;
  signature: string;
  message: string;
}

export interface AuthWalletResponse {
  token: string;
  user: {
    _id: string;
    name: string;
    walletAddress: string;
  };
}

export interface FreeChipsResponse {
  chipsAmount: number;
}

export const gameApi = {
  joinGame: (
    gameId: string,
    data: JoinGameRequest,
  ): Promise<AxiosResponse<JoinGameResponse>> =>
    import('axios').then(({ default: axios }) =>
      axios.post(`/api/games/${gameId}/join`, data),
    ),

  shuffle: (
    gameId: string,
    data: ShuffleRequest,
  ): Promise<AxiosResponse<void>> =>
    import('axios').then(({ default: axios }) =>
      axios.post(`/api/games/${gameId}/shuffle`, data),
    ),

  joinAndShuffle: (
    gameId: string,
    data: JoinAndShuffleRequest,
  ): Promise<AxiosResponse<void>> =>
    import('axios').then(({ default: axios }) =>
      axios.post(`/api/tables/${gameId}/join-and-shuffle`, data),
    ),

  playerAction: (
    gameId: string,
    data: PlayerActionRequest,
  ): Promise<AxiosResponse<void>> =>
    import('axios').then(({ default: axios }) =>
      axios.post(`/api/games/${gameId}/action`, data),
    ),

  submitRevealToken: (
    gameId: string,
    data: RevealTokenRequest,
  ): Promise<AxiosResponse<void>> =>
    import('axios').then(({ default: axios }) =>
      axios.post(`/api/games/${gameId}/reveal-token`, data),
    ),
};
