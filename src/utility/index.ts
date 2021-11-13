import { RuntimeUtility } from './runtime';

/**
 * 文字列を UTF8 バイトエンコードする。(string to Uint8Array)
 */
export function UTF8(STRING: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(STRING);
}

/**
 * 文字列に UTF8 バイトデコードする (Uint8Array to string)
 */
export function UTF8_DECODE(OCTETS: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(OCTETS);
}

/**
 * 文字列を ASCII バイトエンコードする。 (string to Uint8Array)
 */
export function ASCII(STRING: string): Uint8Array {
  const b = new Uint8Array(STRING.length);
  for (let i = 0; i < STRING.length; i++) {
    b[i] = STRING.charCodeAt(i);
  }
  return b;
}

export function HexStr2Uint8Array(hexstr: string, len: number): Uint8Array {
  let ans_str = hexstr;
  if (hexstr.length < len * 2) {
    ans_str = '0'.repeat(len * 2 - hexstr.length) + hexstr;
  }
  const ans_length = ans_str.length / 2;
  const ans = new Uint8Array(ans_length);
  for (let i = 0; i < ans_length; i++) {
    ans[i] = parseInt(ans_str.substr(i * 2, 2), 16);
  }
  return ans;
}

export function Uint8Array2HexStr(arr: Uint8Array, len: number): string {
  const str_arr = Array.from(arr).map(function (e) {
    let hexchar = e.toString(16);
    if (hexchar.length == 1) {
      hexchar = '0' + hexchar;
    }
    return hexchar;
  });
  let ans = str_arr.join('');
  if (ans.length < len * 2) {
    ans = '0'.repeat(len * 2 - ans.length) + ans;
  }
  return ans;
}

/**
 * ２つのバイト列を結合する
 */
export function CONCAT(A: Uint8Array, B: Uint8Array) {
  const ans = new Uint8Array(A.length + B.length);
  ans.set(A);
  ans.set(B, A.length);
  return ans;
}

// ref: https://qiita.com/suin/items/e0f7b7add75092196cd8

/**
 * T のプロパティを全て unknown | undefined 型に変える
 */
export type WouldBe<T> = { [P in keyof T]?: unknown };

/**
 * value を WouldBE<T> かどうか判定する。
 * T のプロパティを持つかもしれないところまで。
 */
export const isObject = <T extends object>(value: unknown): value is WouldBe<T> =>
  typeof value === 'object' && value !== null;

/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
export const BASE64URL: (OCTETS: Uint8Array) => string = RuntimeUtility.BASE64URL;

/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 */
export const BASE64URL_DECODE: (STRING: string) => Uint8Array = RuntimeUtility.BASE64URL_DECODE;
