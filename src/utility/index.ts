import { RuntimeUtility } from './runtime';

/**
 * 文字列を UTF8 バイト列に変換する
 * @param STRING 変換対象の文字列
 * @returns STRING の UTF8 バイト列
 */
export function UTF8(STRING: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(STRING);
}

/**
 * UTF8 バイト列を文字列に変換する
 * @param OCTETS UTF8 バイト列
 * @returns 文字列
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

/**
 * 16進数の文字列を Uint8Array に変換する。
 * len を与えない時は hexstr の長さにする。
 * @param hexstr 16進数の文字列
 * @param len 求めるバイナリ列の長さ。 hexstr の方が大きい時は TypeError を投げる。
 * hexstr の方が短い時は先頭を 0 padding する。
 * @returns hexstr を Uint8Array で表現したもの
 */
export function HexStr2Uint8Array(hexstr: string, len?: number): Uint8Array {
  // len があれば、hexstr で足りない分を先頭 0 padding する。
  // len がないなら、 hexstr が奇数長の場合に先頭 0 padding する
  let ans_str: string;
  if (len) {
    if (hexstr.length <= len * 2) {
      ans_str = '0'.repeat(len * 2 - hexstr.length) + hexstr;
    } else {
      throw new TypeError(`hexstr が len よりも長い`);
    }
  } else {
    if (hexstr.length % 2 === 1) {
      ans_str = '0' + hexstr;
    } else {
      ans_str = hexstr;
    }
  }

  const ans_length = ans_str.length / 2;
  const ans = new Uint8Array(ans_length);
  for (let i = 0; i < ans_length; i++) {
    ans[i] = parseInt(ans_str.substr(i * 2, 2), 16);
  }
  return ans;
}

/**
 * Uint8Array を16進数文字列に変換する。
 * @param arr バイナリ列
 * @param len 16進数文字列にした時のバイナリ長(結果は len の2倍の文字列になる)。
 * arr の方が長い時は TypeError をながる。 arr の方が短い時は先頭を 00-padding する。
 * @returns arr を16進数表現した文字列
 */
export function Uint8Array2HexStr(arr: Uint8Array, len?: number): string {
  const str_arr = Array.from(arr).map(function (e) {
    let hexchar = e.toString(16);
    if (hexchar.length == 1) {
      hexchar = '0' + hexchar;
    }
    return hexchar;
  });
  const ans = str_arr.join('');
  if (len) {
    if (ans.length <= len * 2) {
      return '0'.repeat(len * 2 - ans.length) + ans;
    } else {
      throw new TypeError(`arr が len よりも長い`);
    }
  } else {
    return ans;
  }
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
 * browser なら window.btoa で実装し、 node なら Buffer で実装する。
 */
export const BASE64URL: (OCTETS: Uint8Array) => string = RuntimeUtility.BASE64URL;

/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 * browser なら window.atob で実装し、 node なら Buffer で実装する。
 */
export const BASE64URL_DECODE: (STRING: string) => Uint8Array = RuntimeUtility.BASE64URL_DECODE;
