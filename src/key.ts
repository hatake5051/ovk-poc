import { BN } from 'bn.js';
import { ec } from 'elliptic';
import { BASE64URL, BASE64URL_DECODE, HexStr2Uint8Array, Uint8Array2HexStr, UTF8 } from 'utility';

const p256 = new ec('p256');

export type ECPubJWK = { kty: 'EC'; kid?: string; crv: string; x: string; y: string };

export function equalECPubJWK(l?: ECPubJWK, r?: ECPubJWK): boolean {
  if (!l && !r) return true;
  if (!l || !r) return false;
  return l.kid === r.kid && l.crv === r.crv && l.x === r.x && l.y === r.y;
}

export class ECPubKey {
  private constructor(private _x: Uint8Array, private _y: Uint8Array, private _kid?: string) {}

  get kty(): 'EC' {
    return 'EC';
  }

  async kid(): Promise<string> {
    if (this._kid) {
      return this._kid;
    }
    const json = JSON.stringify({
      crv: this.crv,
      kty: this.kty,
      x: this.x('b64u'),
      y: this.y('b64u'),
    });
    const dgst = await window.crypto.subtle.digest('SHA-256', UTF8(json));
    return BASE64URL(new Uint8Array(dgst));
  }

  get crv(): 'P-256' {
    return 'P-256';
  }

  x(format: 'b64u'): string;
  x(format: 'oct'): Uint8Array;
  x(format: 'b64u' | 'oct'): string | Uint8Array {
    switch (format) {
      case 'b64u':
        return BASE64URL(this._x);
      case 'oct':
        return this._x;
    }
  }

  y(format: 'b64u'): string;
  y(format: 'oct'): Uint8Array;
  y(format: 'b64u' | 'oct'): string | Uint8Array {
    switch (format) {
      case 'b64u':
        return BASE64URL(this._y);
      case 'oct':
        return this._y;
    }
  }

  static async fromPrivKey(pk: ECPrivKey): Promise<ECPubKey> {
    return new ECPubKey(pk.x('oct'), pk.y('oct'), await pk.kid());
  }

  static fromJWK(jwk: ECPubJWK): ECPubKey {
    return new ECPubKey(BASE64URL_DECODE(jwk.x), BASE64URL_DECODE(jwk.y), jwk.kid);
  }

  static is(arg: unknown): arg is ECPubKey {
    return arg instanceof ECPubKey;
  }

  async toJWK(): Promise<ECPubJWK> {
    return {
      kty: this.kty,
      kid: await this.kid(),
      crv: this.crv,
      x: this.x('b64u'),
      y: this.y('b64u'),
    };
  }
}

export type ECPirvJWK = { kty: 'EC'; kid?: string; crv: string; x: string; y: string; d: string };

export class ECPrivKey {
  private constructor(
    private _x: Uint8Array,
    private _y: Uint8Array,
    private _d: Uint8Array,
    private _kid?: string
  ) {}

  get kty(): 'EC' {
    return 'EC';
  }

  get crv(): 'P-256' {
    return 'P-256';
  }

  async kid(): Promise<string> {
    if (this._kid) {
      return this._kid;
    }
    const json = JSON.stringify({
      crv: this.crv,
      kty: this.kty,
      x: this.x('b64u'),
      y: this.y('b64u'),
    });
    const dgst = await window.crypto.subtle.digest('SHA-256', UTF8(json));
    return BASE64URL(new Uint8Array(dgst));
  }

  x(format: 'b64u'): string;
  x(format: 'oct'): Uint8Array;
  x(format: 'b64u' | 'oct'): string | Uint8Array {
    switch (format) {
      case 'b64u':
        return BASE64URL(this._x);
      case 'oct':
        return this._x;
    }
  }

  y(format: 'b64u'): string;
  y(format: 'oct'): Uint8Array;
  y(format: 'b64u' | 'oct'): string | Uint8Array {
    switch (format) {
      case 'b64u':
        return BASE64URL(this._y);
      case 'oct':
        return this._y;
    }
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

  static async fromSecret(d: Uint8Array): Promise<ECPrivKey> {
    const pk = p256.keyFromPrivate(d);
    const d_bytes = HexStr2Uint8Array(pk.getPrivate('hex'), 32);
    const xy_hexstr = pk.getPublic('hex');
    if (!xy_hexstr.startsWith('04')) {
      throw new TypeError(`Cannot convert to JWK`);
    }
    const x_bytes = HexStr2Uint8Array(xy_hexstr.slice(2, 32 * 2 + 2), 32);
    const y_bytes = HexStr2Uint8Array(xy_hexstr.slice(32 * 2 + 2), 32);
    return new ECPrivKey(x_bytes, y_bytes, d_bytes);
  }

  static fromJWK(jwk: ECPirvJWK): ECPrivKey {
    return new ECPrivKey(
      BASE64URL_DECODE(jwk.x),
      BASE64URL_DECODE(jwk.y),
      BASE64URL_DECODE(jwk.d),
      jwk.kid
    );
  }

  static async gen(): Promise<ECPrivKey> {
    const sk_api = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    if (!sk_api.privateKey) {
      throw new TypeError('Extractive になっていない');
    }
    const sk = await window.crypto.subtle.exportKey('jwk', sk_api.privateKey);
    return ECPrivKey.fromJWK(sk as ECPirvJWK);
  }

  async toECPubKey(): Promise<ECPubKey> {
    return ECPubKey.fromPrivKey(this);
  }

  async toJWK(): Promise<ECPirvJWK> {
    return {
      kty: this.kty,
      kid: await this.kid(),
      crv: this.crv,
      x: this.x('b64u'),
      y: this.y('b64u'),
      d: this.d('b64u'),
    };
  }

  async computeDH(pk: ECPubJWK): Promise<ECPubJWK> {
    const keypair = p256.keyFromPublic({
      x: Uint8Array2HexStr(BASE64URL_DECODE(pk.x), 32),
      y: Uint8Array2HexStr(BASE64URL_DECODE(pk.y), 32),
    });
    const bp = keypair.getPublic().mul(new BN(this.d('oct')));
    return {
      kty: 'EC',
      crv: 'P-256',
      x: BASE64URL(HexStr2Uint8Array(bp.getX().toString(16, 32), 32)),
      y: BASE64URL(HexStr2Uint8Array(bp.getY().toString(16, 32), 32)),
    };
  }
}
