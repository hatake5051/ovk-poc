import { RuntimeUtility } from '../runtime';

/**
 * 乱数列を生成する。
 * @param len 生成したいランダム列の長さ(バイト列)
 * @returns 乱数列
 */
export function RandUint8Array(len: number): Uint8Array {
  return RuntimeUtility.getRandomValues(new Uint8Array(len));
}
