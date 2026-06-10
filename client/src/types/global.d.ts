// Window 扩展类型
interface Window {
  socket?: import('socket.io-client').Socket;
  gtag?: (...args: unknown[]) => void;
}
