// Base64 helpers (replacing removed fromB64/toB64 from @mysten/sui/utils)

/**
 * 将 Uint8Array 编码为 base64 字符串。
 *
 * @param bytes 待编码的字节序列
 * @returns base64 编码字符串
 */
export function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * 将 base64 字符串解码为 Uint8Array。
 *
 * @param b64 base64 编码字符串
 * @returns 解码后的字节序列
 */
export function fromB64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
