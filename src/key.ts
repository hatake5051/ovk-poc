import { ec } from 'elliptic';
import { BASE64URL, BASE64URL_DECODE, HexStr2Uint8Array } from 'utility';

export class KID {
  constructor(public kid: string) {}

  static async genKeyHandle(key: Uint8Array, secret: Uint8Array): Promise<KID> {
    const encKey = await window.crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, secret);
    return new KID(BASE64URL(iv) + '.' + BASE64URL(new Uint8Array(enc)));
  }

  async deriveSecret(key: Uint8Array): Promise<Uint8Array> {
    const decKey = await window.crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    const kid_splited = this.kid.split('.');
    if (kid_splited.length !== 2) {
      throw new TypeError('Invalid KID');
    }
    const [iv_b64, ctext_b64] = kid_splited;
    let dec: ArrayBuffer;
    try {
      dec = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: BASE64URL_DECODE(iv_b64) },
        decKey,
        BASE64URL_DECODE(ctext_b64)
      );
    } catch {
      throw new EvalError(`Invalid KID`);
    }
    return new Uint8Array(dec);
  }
}

export type ECPubJWK = { kty: 'EC'; kid: string; crv: string; x: string; y: string };

export class ECPubKey {
  private constructor(public kid: KID, private _x: Uint8Array, private _y: Uint8Array) {}

  get kty(): 'EC' {
    return 'EC';
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

  static fromPrivKey(pk: ECPrivKey): ECPubKey {
    return new ECPubKey(pk.kid, pk.x('oct'), pk.y('oct'));
  }

  static fromJWK(jwk: ECPubJWK): ECPubKey {
    return new ECPubKey(new KID(jwk.kid), BASE64URL_DECODE(jwk.x), BASE64URL_DECODE(jwk.y));
  }

  static is(arg: unknown): arg is ECPubKey {
    return arg instanceof ECPubKey;
  }

  toJWK(): ECPubJWK {
    return {
      kty: this.kty,
      kid: this.kid.kid,
      crv: this.crv,
      x: this.x('b64u'),
      y: this.y('b64u'),
    };
  }

  toString(): string {
    return JSON.stringify(this.toJWK());
  }
}

export type ECPirvJWK = { kty: 'EC'; kid: string; crv: string; x: string; y: string; d: string };

export class ECPrivKey {
  private constructor(
    public kid: KID,
    private _x: Uint8Array,
    private _y: Uint8Array,
    private _d: Uint8Array
  ) {}

  get kty(): 'EC' {
    return 'EC';
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

  static fromPubKeyWithSecret(pk: ECPubKey, d: Uint8Array): ECPrivKey {
    return new ECPrivKey(pk.kid, pk.x('oct'), pk.y('oct'), d);
  }

  static fromECKeyPair(pk: ec.KeyPair, kid: KID): ECPrivKey {
    const d_bytes = HexStr2Uint8Array(pk.getPrivate('hex'));
    const xy_hexstr = pk.getPublic('hex');
    if (!xy_hexstr.startsWith('04')) {
      throw new TypeError(`Cannot convert to JWK`);
    }
    const x_bytes = HexStr2Uint8Array(xy_hexstr.slice(2, 32 * 2 + 2));
    const y_bytes = HexStr2Uint8Array(xy_hexstr.slice(32 * 2 + 2));
    return new ECPrivKey(kid, x_bytes, y_bytes, d_bytes);
  }

  static fromJWK(jwk: ECPirvJWK): ECPrivKey {
    return new ECPrivKey(
      new KID(jwk.kid),
      BASE64URL_DECODE(jwk.x),
      BASE64URL_DECODE(jwk.y),
      BASE64URL_DECODE(jwk.d)
    );
  }

  toECPubKey(): ECPubKey {
    return ECPubKey.fromPrivKey(this);
  }

  toJWK(): ECPirvJWK {
    return {
      kty: this.kty,
      kid: this.kid.kid,
      crv: this.crv,
      x: this.x('b64u'),
      y: this.y('b64u'),
      d: this.d('b64u'),
    };
  }
}
