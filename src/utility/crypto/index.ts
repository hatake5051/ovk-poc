import {
  ASCII,
  BASE64URL,
  BASE64URL_DECODE,
  CONCAT,
  HexStr2Uint8Array,
  Uint8Array2HexStr,
  UTF8,
  UTF8_DECODE,
} from 'utility';
import { RuntimeUtility } from '../runtime';
import { KeyPair, secp256r1 } from './curve';
import { RandUint8Array } from './random';

/**
 * 乱数列を生成する。
 * @param len 生成したいランダム列の長さ(バイト列)
 * @returns 乱数列
 */
export { RandUint8Array };

/**
 * Hash 関数を用いた鍵導出関数を実装する。
 * @param key マスター鍵
 * @param salt ソルト。これは公開される。
 * @param length 出力結果の長さ(オクテット長)
 * @returns key を持つ人だけが導出できる鍵
 */
export const HKDF = async (
  key: Uint8Array,
  salt: Uint8Array,
  length: number
): Promise<Uint8Array> => {
  const k = await RuntimeUtility.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits']);
  const derivedKeyMaterial = await RuntimeUtility.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array() },
    k,
    length
  );
  return new Uint8Array(derivedKeyMaterial);
};

/**
 * SHA-256 ハッシュ関数を実装する。
 * @param m メッセージ
 * @returns メッセージの SHA-256 ハッシュ値
 */
export const SHA256 = async (m: Uint8Array): Promise<Uint8Array> => {
  const dgst = await RuntimeUtility.subtle.digest('SHA-256', m);
  return new Uint8Array(dgst);
};

/**
 * HMAC を実装する。
 * mac で MAC 値を生成し、 verify で MAC を検証する。
 */
export const HMAC = {
  /**
   * MAC を生成する
   * @param key MAC 生成鍵(検証鍵でもある)
   * @param m メッセージ
   * @returns MAC 値
   */
  async mac(key: Uint8Array, m: Uint8Array): Promise<Uint8Array> {
    const sk_api = await RuntimeUtility.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const mac = await RuntimeUtility.subtle.sign('HMAC', sk_api, m);
    return new Uint8Array(mac);
  },
  /**
   * MAC を検証する。
   * @param key MAC 検証鍵(生成鍵でもある)
   * @param m メッセージ
   * @param mac MAC 値
   * @returns 検証に成功すれば true
   */
  async verify(key: Uint8Array, m: Uint8Array, mac: Uint8Array): Promise<boolean> {
    const sk_api = await RuntimeUtility.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    return await RuntimeUtility.subtle.verify('HMAC', sk_api, mac, m);
  },
};

/**
 * ECDSA over P-256 を実装する。
 * gen で EC 秘密鍵を生成もしくは、秘密鍵から公開鍵を導出する。
 * sign で署名を行い、 verify で署名を検証する。
 * dh で DH 計算を行う。
 */
export const ECP256 = {
  /**
   * 秘密鍵を生成する。
   * @param secret 秘密鍵成分
   * @returns 秘密鍵成分から導出した公開鍵を含む秘密鍵
   */
  async gen(secret?: Uint8Array): Promise<JsonWebKey> {
    const d = secret ? BigInt('0x' + Uint8Array2HexStr(secret, secret.length)) : undefined;
    return KeyPair.gen(secp256r1, d).toJWK();
  },
  /**
   * 秘密鍵でメッセージの署名値を作成する。
   * @param sk EC秘密鍵
   * @param m メッセージ
   * @returns 署名値
   */
  async sign(sk: JsonWebKey, m: Uint8Array): Promise<Uint8Array> {
    const k_api = await RuntimeUtility.subtle.importKey(
      'jwk',
      sk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    const sig = await RuntimeUtility.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k_api, m);
    return new Uint8Array(sig);
  },
  /**
   * 公開鍵で署名を検証する。
   * @param pk EC公開鍵
   * @param m メッセージ
   * @param s 署名値
   * @returns 署名が正しければ true
   */
  async verify(pk: JsonWebKey, m: Uint8Array, s: Uint8Array): Promise<boolean> {
    const k = await RuntimeUtility.subtle.importKey(
      'jwk',
      pk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await RuntimeUtility.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, s, m);
  },

  /**
   * DH計算を行う。
   * @param pk EC 公開鍵成分
   * @param sk EC 秘密鍵成分
   * @returns sk * pk した結果
   */
  async dh(pk: { x: string; y: string }, sk: { d: string }): Promise<JsonWebKey> {
    const privKey = KeyPair.gen(
      secp256r1,
      BigInt('0x' + Uint8Array2HexStr(BASE64URL_DECODE(sk.d), 32))
    );
    const pubKey = {
      x: BigInt('0x' + Uint8Array2HexStr(BASE64URL_DECODE(pk.x), 32)),
      y: BigInt('0x' + Uint8Array2HexStr(BASE64URL_DECODE(pk.y), 32)),
    };
    const bp = privKey.computeDH(pubKey);
    return {
      kty: 'EC',
      crv: 'P-256',
      x: BASE64URL(HexStr2Uint8Array(bp.x.toString(16), 32)),
      y: BASE64URL(HexStr2Uint8Array(bp.y.toString(16), 32)),
    };
  },
};

/**
 * PBES2 + A128GCM の JWE Compact Serialization 実装。
 * パスワードから Key Encryption Key を導出し、 Content Encryption Key をラップする。
 * CEK で平文を AES-GCM using 128 bit key 暗号化する。
 * compact で暗号化し JWE で表現、 dec で JWE を復号する。
 */
export const PBES2JWE = {
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
    const cek_api = await RuntimeUtility.subtle.importKey('raw', cek, 'AES-GCM', true, ['encrypt']);
    // CEK を使って m を暗号化
    const iv = RandUint8Array(12);
    const e = new Uint8Array(
      await RuntimeUtility.subtle.encrypt(
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
    const dk_api = await RuntimeUtility.subtle.importKey(
      'raw',
      await RuntimeUtility.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
          iterations: header.p2c,
        },
        await RuntimeUtility.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']),
        128
      ),
      { name: 'AES-KW' },
      false,
      ['wrapKey']
    );
    const ek = new Uint8Array(
      await RuntimeUtility.subtle.wrapKey('raw', cek_api, dk_api, { name: 'AES-KW' })
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
    const dk_api = await RuntimeUtility.subtle.importKey(
      'raw',
      await RuntimeUtility.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
          iterations: header.p2c,
        },
        await RuntimeUtility.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']),
        128
      ),
      { name: 'AES-KW' },
      false,
      ['unwrapKey']
    );
    const cek_api = await RuntimeUtility.subtle.unwrapKey(
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
    const e = await RuntimeUtility.subtle.decrypt(
      { name: 'AES-GCM', iv: BASE64URL_DECODE(iv_b64u), additionalData: ASCII(h_b64u) },
      cek_api,
      CONCAT(BASE64URL_DECODE(c_b64u), BASE64URL_DECODE(atag_b64u))
    );
    return new Uint8Array(e);
  },
};
