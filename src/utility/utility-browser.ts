import { BN } from 'bn.js';
import { ec } from 'elliptic';
import {
  ASCII,
  CONCAT,
  HexStr2Uint8Array,
  Uint8Array2HexStr,
  UTF8,
  UTF8_DECODE,
} from './utility-base';

/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
function BASE64URL(OCTETS: Uint8Array): string {
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
function BASE64URL_DECODE(STRING: string) {
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

/**
 * 乱数列を生成する。
 * @param len 生成したいランダム列の長さ(バイト列)
 * @returns 乱数列
 */
function RandUint8Array(len: number): Uint8Array {
  return window.crypto.getRandomValues(new Uint8Array(len));
}

const HKDF = async (key: Uint8Array, salt: Uint8Array, length: number): Promise<Uint8Array> => {
  const k = await window.crypto.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits']);
  const derivedKeyMaterial = await window.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array() },
    k,
    length
  );
  return new Uint8Array(derivedKeyMaterial);
};

const SHA256 = async (m: Uint8Array): Promise<Uint8Array> => {
  const dgst = await window.crypto.subtle.digest('SHA-256', m);
  return new Uint8Array(dgst);
};

const HMAC = {
  async mac(key: Uint8Array, m: Uint8Array): Promise<Uint8Array> {
    const sk_api = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const mac = await window.crypto.subtle.sign('HMAC', sk_api, m);
    return new Uint8Array(mac);
  },
  async verify(key: Uint8Array, m: Uint8Array, mac: Uint8Array): Promise<boolean> {
    const sk_api = await window.crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    return await window.crypto.subtle.verify('HMAC', sk_api, mac, m);
  },
};

const p256 = new ec('p256');
const ECP256 = {
  async gen(secret?: Uint8Array): Promise<JsonWebKey> {
    if (secret) {
      const pk = p256.keyFromPrivate(secret);
      const d_bytes = HexStr2Uint8Array(pk.getPrivate('hex'), 32);
      const xy_hexstr = pk.getPublic('hex');
      if (!xy_hexstr.startsWith('04')) {
        throw new TypeError(`Cannot convert to JWK`);
      }
      const x_bytes = HexStr2Uint8Array(xy_hexstr.slice(2, 32 * 2 + 2), 32);
      const y_bytes = HexStr2Uint8Array(xy_hexstr.slice(32 * 2 + 2), 32);
      return {
        kty: 'EC',
        crv: 'P-256',
        d: BASE64URL(d_bytes),
        x: BASE64URL(x_bytes),
        y: BASE64URL(y_bytes),
      };
    }
    const sk_api = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    if (!sk_api.privateKey) {
      throw new TypeError('Extractive になっていない');
    }
    const sk = await window.crypto.subtle.exportKey('jwk', sk_api.privateKey);
    return sk;
  },

  async sign(sk: JsonWebKey, m: Uint8Array): Promise<Uint8Array> {
    const k_api = await window.crypto.subtle.importKey(
      'jwk',
      sk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    const sig = await window.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k_api, m);
    return new Uint8Array(sig);
  },

  async verify(pk: JsonWebKey, m: Uint8Array, s: Uint8Array): Promise<boolean> {
    const k = await window.crypto.subtle.importKey(
      'jwk',
      pk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await window.crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, s, m);
  },

  async dh(pk: { x: string; y: string }, sk: { d: string }): Promise<JsonWebKey> {
    const keypair = p256.keyFromPublic({
      x: Uint8Array2HexStr(BASE64URL_DECODE(pk.x), 32),
      y: Uint8Array2HexStr(BASE64URL_DECODE(pk.y), 32),
    });
    const bp = keypair.getPublic().mul(new BN(BASE64URL_DECODE(sk.d)));
    return {
      kty: 'EC',
      crv: 'P-256',
      x: BASE64URL(HexStr2Uint8Array(bp.getX().toString(16, 32), 32)),
      y: BASE64URL(HexStr2Uint8Array(bp.getY().toString(16, 32), 32)),
    };
  },
};

const PBES2JWE = {
  async compact(pw: string, m: Uint8Array): Promise<string> {
    // PBES2 用の JOSE Header を用意して
    const header = {
      alg: 'PBES2-HS256+A128KW',
      enc: 'A128GCM',
      p2c: 1000,
      p2s: BASE64URL(RandUint8Array(16)),
    };
    const header_b64u = BASE64URL(UTF8(JSON.stringify(header)));

    // Content Encryption Key を乱数生成する
    const cek = RandUint8Array(16);
    const cek_api = await window.crypto.subtle.importKey('raw', cek, 'AES-GCM', true, ['encrypt']);
    // CEK を使って m を暗号化
    const iv = RandUint8Array(12);
    const e = new Uint8Array(
      await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: ASCII(header_b64u),
        },
        cek_api,
        m
      )
    );
    const ciphertext = e.slice(0, e.length - 16);
    const atag = e.slice(e.length - 16);

    // PBES2 で導出した鍵で CEK をラップして Encrypted Key を生成する
    const dk_api = await window.crypto.subtle.importKey(
      'raw',
      await window.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
          iterations: header.p2c,
        },
        await window.crypto.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']),
        128
      ),
      { name: 'AES-KW' },
      false,
      ['wrapKey']
    );
    const ek = new Uint8Array(
      await window.crypto.subtle.wrapKey('raw', cek_api, dk_api, { name: 'AES-KW' })
    );
    const ek_b64u = BASE64URL(ek);

    return `${header_b64u}.${ek_b64u}.${BASE64URL(iv)}.${BASE64URL(ciphertext)}.${BASE64URL(atag)}`;
  },

  async dec(pw: string, compact: string): Promise<Uint8Array> {
    const l = compact.split('.');
    if (l.length !== 5) {
      throw new EvalError('JWE Compact Serialization の形式ではない');
    }
    const [h_b64u, ek_b64u, iv_b64u, c_b64u, atag_b64u] = l;
    const header = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(h_b64u)));

    // PBES2 で導出した鍵で EK をアンラップして CEK を得る
    const dk_api = await window.crypto.subtle.importKey(
      'raw',
      await window.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
          iterations: header.p2c,
        },
        await window.crypto.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']),
        128
      ),
      { name: 'AES-KW' },
      false,
      ['unwrapKey']
    );
    const cek_api = await window.crypto.subtle.unwrapKey(
      'raw',
      BASE64URL_DECODE(ek_b64u),
      dk_api,
      {
        name: 'AES-KW',
      },
      'AES-GCM',
      true,
      ['decrypt']
    );
    // CEK を使って ciphertext と authentication tag から平文を復号し整合性を検証する
    const e = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: BASE64URL_DECODE(iv_b64u), additionalData: ASCII(h_b64u) },
      cek_api,
      CONCAT(BASE64URL_DECODE(c_b64u), BASE64URL_DECODE(atag_b64u))
    );
    return new Uint8Array(e);
  },
};

export const RuntimeUtility = {
  BASE64URL,
  BASE64URL_DECODE,
  RandUint8Array,
  HKDF,
  SHA256,
  HMAC,
  ECP256,
  PBES2JWE,
};
