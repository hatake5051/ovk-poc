import { ec } from 'elliptic';
import { BASE64URL, BASE64URL_DECODE, CONCAT, HexStr2Uint8Array, UTF8 } from 'utility';

export function newSeedDeriver(): SeedDeriver {
  return new SeedImple([{ s: UTF8('Hello, World') }], UTF8('abcdefghijklmnop'));
}

interface SeedDeriver {
  deriveOVK(r: Uint8Array): Promise<ECPubKey>;
  macOVK(OVK: ECPubKey, svcID: string): Promise<Uint8Array>;
  macOVK(r: Uint8Array, svcID: string): Promise<Uint8Array>;
  verifyOVK(OVK: ECPubKey, svcID: string, MAC: Uint8Array): Promise<boolean>;
  signOVK(r: Uint8Array, cred: Uint8Array): Promise<Uint8Array>;
  signOVK(OVK: ECPubKey, cred: Uint8Array): Promise<Uint8Array>;
}

interface SeedNavigator {
  startKeyAgreement: () => Promise<ECPubKey>;
  agree: (received: ECPubKey) => Promise<boolean>;
  migrated: () => Promise<boolean>;
}

class ECPubKey {
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

  static is(arg: unknown): arg is ECPubKey {
    return arg instanceof ECPubKey;
  }

  toJWK(): { kty: 'EC'; crv: string; x: string; y: string } {
    return { kty: this.kty, crv: this.crv, x: this.x('b64u'), y: this.y('b64u') };
  }

  toString(): string {
    return JSON.stringify(this.toJWK());
  }
}

class ECPrivKey {
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

  toECPubKey(): ECPubKey {
    return ECPubKey.fromPrivKey(this);
  }

  toJWK(): { kty: 'EC'; crv: string; x: string; y: string; d: string } {
    return {
      kty: this.kty,
      crv: this.crv,
      x: this.x('b64u'),
      y: this.y('b64u'),
      d: this.d('b64u'),
    };
  }
}

class SeedImple implements SeedDeriver {
  constructor(private seeds: { s: Uint8Array }[], private key: Uint8Array) {}

  private get seed(): Uint8Array {
    if (this.seeds.length != 1) {
      throw new RangeError('Seed を一意に識別できなかった');
    }
    const { s } = this.seeds[0];
    return s;
  }

  private async OVK(r: Uint8Array): Promise<ECPrivKey> {
    const d = await kdf(this.seed, r, 256);
    const kid = await KID.genKeyHandle(this.key, r);
    const sk = await deriveSK(d, kid);
    return sk;
  }

  async deriveOVK(r: Uint8Array): Promise<ECPubKey> {
    const sk = await this.OVK(r);
    return sk.toECPubKey();
  }

  async macOVK(x: ECPubKey | Uint8Array, svcID: string): Promise<Uint8Array> {
    let r: Uint8Array;
    if (ECPubKey.is(x)) {
      r = await x.kid.deriveSecret(this.key);
    } else {
      r = x;
    }
    const sk = await this.OVK(r);
    const sk_api = await window.crypto.subtle.importKey(
      'raw',
      sk.d('oct'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const mac = await window.crypto.subtle.sign('HMAC', sk_api, CONCAT(r, UTF8(svcID)));
    return new Uint8Array(mac);
  }

  async verifyOVK(OVK: ECPubKey, svcID: string, MAC: Uint8Array): Promise<boolean> {
    const r = await OVK.kid.deriveSecret(this.key);
    const sk = await this.OVK(r);
    const sk_api = await window.crypto.subtle.importKey(
      'raw',
      sk.d('oct'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    return await window.crypto.subtle.verify('HMAC', sk_api, MAC, CONCAT(r, UTF8(svcID)));
  }

  async signOVK(x: ECPubKey | Uint8Array, cred: Uint8Array): Promise<Uint8Array> {
    let r: Uint8Array;
    if (ECPubKey.is(x)) {
      r = await x.kid.deriveSecret(this.key);
    } else {
      r = x;
    }
    const sk = await this.OVK(r);
    const sk_api = await window.crypto.subtle.importKey(
      'jwk',
      sk.toJWK(),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    const sig = await window.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, sk_api, cred);
    return new Uint8Array(sig);
  }
}

async function kdf(kdfkey: Uint8Array, salt: Uint8Array, length: number): Promise<Uint8Array> {
  const key = await window.crypto.subtle.importKey('raw', kdfkey, 'HKDF', false, ['deriveBits']);
  const derivedKeyMaterial = await window.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array() },
    key,
    length
  );
  return new Uint8Array(derivedKeyMaterial);
}

class KID {
  private constructor(private kid: string) {}

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

async function deriveSK(secret: Uint8Array, kid: KID): Promise<ECPrivKey> {
  const pk = new ec('p256').keyFromPrivate(secret);
  return ECPrivKey.fromECKeyPair(pk, kid);
}
