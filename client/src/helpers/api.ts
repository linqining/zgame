import axios, { AxiosResponse } from 'axios';

const API_BASE = '/api';

export const gameApi = {
  joinGame: (gameId: string, data: Record<string, unknown>): Promise<AxiosResponse> =>
    axios.post(`${API_BASE}/games/${gameId}/join`, data),

  shuffle: (gameId: string, data: Record<string, unknown>): Promise<AxiosResponse> =>
    axios.post(`${API_BASE}/games/${gameId}/shuffle`, data),

  joinAndShuffle: (gameId: string, data: Record<string, unknown>): Promise<AxiosResponse> =>
    axios.post(`${API_BASE}/tables/${gameId}/join-and-shuffle`, data),

  playerAction: (gameId: string, data: Record<string, unknown>): Promise<AxiosResponse> =>
    axios.post(`${API_BASE}/games/${gameId}/action`, data),

  submitRevealToken: (gameId: string, data: Record<string, unknown>): Promise<AxiosResponse> =>
    axios.post(`${API_BASE}/games/${gameId}/reveal-token`, data),
};
