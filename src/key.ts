import { BASE64URL, BASE64URL_DECODE, ECP256, isObject, SHA256, UTF8 } from 'utility';

/**
 * EC 公開鍵 をJWKで表現する
 */
export type ECPubJWK = { kty: 'EC'; kid?: string; crv: 'P-256'; x: string; y: string };

export const isECPubJWK = (arg: unknown): arg is ECPubJWK =>
  isObject<ECPubJWK>(arg) &&
  arg.kty === 'EC' &&
  (!arg.kid || typeof arg.kid === 'string') &&
  typeof arg.crv === 'string' &&
  typeof arg.x === 'string' &&
  typeof arg.y === 'string';

/**
 * ２つの ECPubJWK が等しいかどうか判定する
 * @param l ECPubJWK で undefined でも良い;
 * @param r ECPubJWK で undefined でも良い;
 * @returns 二つの ECPubJWK のプロパティが全て等しければ true
 */
export function equalECPubJWK(l?: ECPubJWK, r?: ECPubJWK): boolean {
  if (!l && !r) return true;
  if (!l || !r) return false;
  return l.kid === r.kid && l.crv === r.crv && l.x === r.x && l.y === r.y;
}

/**
 * EC 秘密鍵を JWK で表現する。
 */
export type ECPirvJWK = { d: string } & ECPubJWK;

export const isECPirvJWK = (arg: unknown): arg is ECPirvJWK =>
  isObject<ECPirvJWK>(arg) && typeof arg.d === 'string' && isECPubJWK(arg);

/**
 * EC 公開鍵を表現するクラス。
 * 署名の検証や kid の命名など行える。
 */
export class ECPubKey {
  protected constructor(
    protected _x: Uint8Array,
    protected _y: Uint8Array,
    protected _kid: string
  ) {}

  /**
   * 公開鍵の x 座標を表現する
   * @param format base64url か octet 表現か選択する
   * @returns base64url なら string で octet なら Uint8Array
   */
  protected x(format: 'b64u'): string;
  protected x(format: 'oct'): Uint8Array;
  protected x(format: 'b64u' | 'oct'): string | Uint8Array {
    switch (format) {
      case 'b64u':
        return BASE64URL(this._x);
      case 'oct':
        return this._x;
    }
  }

  /**
   * 公開鍵の y 座標を表現する
   * @param format base64url か octet 表現か選択する
   * @returns base64url なら string で octet なら Uint8Array
   */
  protected y(format: 'b64u'): string;
  protected y(format: 'oct'): Uint8Array;
  protected y(format: 'b64u' | 'oct'): string | Uint8Array {
    switch (format) {
      case 'b64u':
        return BASE64URL(this._y);
      case 'oct':
        return this._y;
    }
  }

  static async fromJWK(jwk: ECPubJWK): Promise<ECPubKey> {
    return new ECPubKey(
      BASE64URL_DECODE(jwk.x),
      BASE64URL_DECODE(jwk.y),
      jwk.kid ?? (await genKID(jwk))
    );
  }

  static is(arg: unknown): arg is ECPubKey {
    return arg instanceof ECPubKey;
  }
  /**
   * この公開鍵を JWK で表現する。
   * @returns EC公開鍵の JWK 表現
   */
  toJWK(): ECPubJWK {
    return {
      kty: 'EC',
      kid: this._kid,
      crv: 'P-256',
      x: this.x('b64u'),
      y: this.y('b64u'),
    };
  }

  /**
   * この公開鍵を使って署名値の検証を行う
   * @param m 署名対象のメッセージ
   * @param s 署名値
   * @returns 署名の検証に成功すれば true
   */
  async verify(m: Uint8Array, s: Uint8Array): Promise<boolean> {
    return ECP256.verify(this.toJWK(), m, s);
  }
}

/**
 * EC 秘密鍵を表現する。
 */
export class ECPrivKey extends ECPubKey {
  private constructor(_x: Uint8Array, _y: Uint8Array, private _d: Uint8Array, kid: string) {
    super(_x, _y, kid);
  }

  d(format: 'b64u'): string;
  d(format: 'oct'): Uint8Array;
  d(format: 'b64u' | 'oct'): string | Uint8Array {
    switch (format) {
      case 'b64u':
        return BASE64URL(this._d);
      case 'oct':
        return this._d;
    }
  }

  /**
   * 秘密鍵成分から EC 公開鍵を導出して ECPrivKey を作成するコンストラクタ
   * @param d 秘密鍵の d
   * @returns Promise<ECPrivKey>
   */
  static async fromSecret(d: Uint8Array): Promise<ECPrivKey> {
    return ECPrivKey.fromJWK((await ECP256.gen(d)) as ECPirvJWK);
  }

  /**
   * JWK からECPrivKey を作成するコンストラクタ
   * @param jwk EC 秘密鍵の JWK 成分
   * @returns Promise<ECPrivKey>
   */
  static async fromJWK(jwk: ECPirvJWK): Promise<ECPrivKey> {
    return new ECPrivKey(
      BASE64URL_DECODE(jwk.x),
      BASE64URL_DECODE(jwk.y),
      BASE64URL_DECODE(jwk.d),
      jwk.kid ?? (await genKID(jwk))
    );
  }

  /**
   * ランダムに ECPrivKey を作成するコンストラクタ
   * @returns Promise<ECPrivKey>
   */
  static async gen(): Promise<ECPrivKey> {
    return ECPrivKey.fromJWK((await ECP256.gen()) as ECPirvJWK);
  }

  toECPubKey(): ECPubKey {
    return this;
  }

  toJWK(): ECPirvJWK {
    return {
      ...super.toJWK(),
      d: this.d('b64u'),
    };
  }

  /**
   * ECDH を行う
   * @param pk EC 公開鍵
   * @returns (this.d) * pk した結果の EC 公開鍵
   */
  async computeDH(pk: ECPubJWK): Promise<ECPubJWK> {
    return (await ECP256.dh(pk, this.toJWK())) as ECPubJWK;
  }

  /**
   * この秘密鍵を使ってメッセージに対して署名する。
   * @param m 署名対象のメッセージ
   * @returns 署名値
   */
  async sign(m: Uint8Array): Promise<Uint8Array> {
    return ECP256.sign(this.toJWK(), m);
  }
}

/**
 * RFC 7638 - JSON Web Key (JWK) Thumbprint に基づいて kid を生成する。
 * @param jwk KID 生成対象
 * @returns jwk.kid
 */
async function genKID(jwk: ECPubJWK | ECPirvJWK): Promise<string> {
  const json = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  const dgst = await SHA256(UTF8(json));
  return BASE64URL(dgst);
}
