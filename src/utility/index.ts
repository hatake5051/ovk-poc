import {
  ASCII,
  CONCAT,
  HexStr2Uint8Array,
  isObject,
  Uint8Array2HexStr,
  UTF8,
  UTF8_DECODE,
  WouldBe,
} from './utility-base';
import { RuntimeUtility } from './utility-browser';

export {
  UTF8,
  UTF8_DECODE,
  ASCII,
  HexStr2Uint8Array,
  Uint8Array2HexStr,
  CONCAT,
  WouldBe,
  isObject,
};

/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
export const BASE64URL: (OCTETS: Uint8Array) => string = RuntimeUtility.BASE64URL;

/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 */
export const BASE64URL_DECODE: (STRING: string) => Uint8Array = RuntimeUtility.BASE64URL_DECODE;

/**
 * 乱数列を生成する。
 * @param len 生成したいランダム列の長さ(バイト列)
 * @returns 乱数列
 */
export const RandUint8Array: (len: number) => Uint8Array = RuntimeUtility.RandUint8Array;

export const HKDF = RuntimeUtility.HKDF;

export const SHA256 = RuntimeUtility.SHA256;

export const HMAC = RuntimeUtility.HMAC;

export const ECP256 = RuntimeUtility.ECP256;

export const PBES2JWE = RuntimeUtility.PBES2JWE;
