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
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
export function BASE64URL(OCTETS: Uint8Array): string {
  // window 組み込みの base64 encode 関数
  // 組み込みの関数は引数としてバイナリ文字列を要求するため
  // Uint8Array をバイナリ文字列へと変換する
  const b_str = String.fromCharCode(...OCTETS);
  const base64_encode = window.btoa(b_str);
  return (
    base64_encode
      // 文字「+」は全て「-」へ変換する
      .replaceAll('+', '-')
      // 文字「/」は全て「_」へ変換する
      .replaceAll('/', '_')
      // 4の倍数にするためのパディング文字は全て消去
      .replaceAll('=', '')
  );
}

/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 */
export function BASE64URL_DECODE(STRING: string) {
  const url_decode = STRING
    // URL-safe にするために変換した文字たちを戻す
    .replaceAll('-', '+')
    .replaceAll('_', '/')
    // 文字列長が4の倍数になるように padding文字で埋める
    .padEnd(Math.ceil(STRING.length / 4) * 4, '=');
  // window 組み込みの base64 decode 関数
  // この関数はデコードの結果をバイナリ文字列として出力する
  const b_str = window.atob(url_decode);
  // バイナリ文字列を Uint8Array に変換する
  const b = new Uint8Array(b_str.length);
  for (let i = 0; i < b_str.length; i++) {
    b[i] = b_str.charCodeAt(i);
  }
  return b;
}

export function HexStr2Uint8Array(hexstr: string): Uint8Array {
  const ans_str = hexstr.length % 2 === 0 ? hexstr : '0' + hexstr;
  const ans_length = ans_str.length / 2;
  const ans = new Uint8Array(ans_length);
  for (let i = 0; i < ans_length; i++) {
    ans[i] = parseInt(ans_str.substr(i * 2, 2), 16);
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
