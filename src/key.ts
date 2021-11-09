import { BASE64URL, BASE64URL_DECODE, ECP256, isObject, SHA256, UTF8 } from 'utility';

export type ECPubJWK = { kty: 'EC'; kid?: string; crv: string; x: string; y: string };

export const isECPubJWK = (arg: unknown): arg is ECPubJWK =>
  isObject<ECPubJWK>(arg) &&
  arg.kty === 'EC' &&
  (!arg.kid || typeof arg.kid === 'string') &&
  typeof arg.crv === 'string' &&
  typeof arg.x === 'string' &&
  typeof arg.y === 'string';

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
    const dgst = await SHA256(UTF8(json));
    return BASE64URL(dgst);
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

  async verify(m: Uint8Array, s: Uint8Array): Promise<boolean> {
    return ECP256.verify(await this.toJWK(), m, s);
  }
}

export type ECPirvJWK = { kty: 'EC'; kid?: string; crv: string; x: string; y: string; d: string };

export const isECPirvJWK = (arg: unknown): arg is ECPirvJWK =>
  isObject<ECPirvJWK>(arg) && typeof arg.d === 'string' && isECPubJWK(arg);

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
    const dgst = await SHA256(UTF8(json));
    return BASE64URL(dgst);
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
    return ECPrivKey.fromJWK((await ECP256.gen(d)) as ECPirvJWK);
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
    return ECPrivKey.fromJWK((await ECP256.gen()) as ECPirvJWK);
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
    return (await ECP256.dh(pk, await this.toJWK())) as ECPubJWK;
  }

  async sign(m: Uint8Array): Promise<Uint8Array> {
    return ECP256.sign(await this.toJWK(), m);
  }
}
