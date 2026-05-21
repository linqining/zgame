import axios from 'axios';

const API_BASE = '/api';

export const gameApi = {
  joinGame: (gameId, data) =>
    axios.post(`${API_BASE}/games/${gameId}/join`, data),

  shuffle: (gameId, data) =>
    axios.post(`${API_BASE}/games/${gameId}/shuffle`, data),

  joinAndShuffle: (gameId, data) =>
    axios.post(`${API_BASE}/tables/${gameId}/join-and-shuffle`, data),
  
  playerAction: (gameId, data) =>
    axios.post(`${API_BASE}/games/${gameId}/action`, data),

  submitRevealToken: (gameId, data) =>
    axios.post(`${API_BASE}/games/${gameId}/reveal-token`, data),
};
