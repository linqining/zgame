import { GameState } from './secretPokerClient'

type MessageHandler = (data: GameState) => void
type ErrorHandler = (error: Event) => void
type CloseHandler = () => void

export class GameWsClient {
  private ws: WebSocket | null = null
  private gameId: string = ''
  private baseUrl: string = ''
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private onMessage: MessageHandler | null = null
  private onError: ErrorHandler | null = null
  private onClose: CloseHandler | null = null
  private intentionalClose = false

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || ''
  }

  connect(gameId: string, handlers: {
    onMessage: MessageHandler
    onError?: ErrorHandler
    onClose?: CloseHandler
  }) {
    this.disconnect()
    this.gameId = gameId
    this.onMessage = handlers.onMessage
    this.onError = handlers.onError || (() => {})
    this.onClose = handlers.onClose || (() => {})
    this.intentionalClose = false

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = this.baseUrl || `${window.location.host}`
    const url = `${protocol}//${host}/api/games/${gameId}/ws`

    this.ws = new WebSocket(url)

    this.ws.onopen = () => {
      console.log(`[WS] Connected to game ${gameId}`)
    }

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as GameState
        if (this.onMessage) {
          this.onMessage(data)
        }
      } catch (e) {
        console.error(`[WS] Failed to parse message:`, e)
      }
    }

    this.ws.onerror = (event) => {
      if (this.onError) this.onError(event)
    }

    this.ws.onclose = () => {
      if (!this.intentionalClose && this.onClose) {
        this.onClose()
      }
      this.scheduleReconnect()
    }
  }

  send(data: object) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }

  disconnect() {
    this.intentionalClose = true
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.ws) {
      this.ws.close(1000, 'Client disconnecting')
      this.ws = null
    }
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }

  private scheduleReconnect() {
    if (this.intentionalClose) return
    this.reconnectTimer = setTimeout(() => {
      if (!this.intentionalClose && !this.isConnected) {
        this.connect(this.gameId, {
          onMessage: this.onMessage!,
          onError: this.onError!,
          onClose: this.onClose!,
        })
      }
    }, 3000)
  }
}

export const gameWsClient = new GameWsClient()
