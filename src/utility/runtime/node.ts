/**
 * node では webcryoto がライブラリで提供されているのでそれを使う。
 * BASE64 関連は Buffer で実装する。
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { subtle, getRandomValues } = require('crypto').webcrypto;

/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
function BASE64URL(OCTETS: Uint8Array): string {
  return Buffer.from(OCTETS).toString('base64url');
}

/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 */
function BASE64URL_DECODE(STRING: string): Uint8Array {
  return Buffer.from(STRING, 'base64url');
}

export const RuntimeUtility = {
  BASE64URL,
  BASE64URL_DECODE,
  subtle,
  getRandomValues,
};
