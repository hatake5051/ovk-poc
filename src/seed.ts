import { ec } from 'elliptic';
import { ECPirvJWK, ECPrivKey, ECPubJWK, ECPubKey, KID } from 'key';
import { BASE64URL, BASE64URL_DECODE, CONCAT, UTF8 } from 'utility';

export type Seed = SeedDeriver & SeedNavigator;

export function newSeed(): Seed {
  return new SeedImple();
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
  startKeyAgreement(): Promise<ECPubKey>;
  agree(received: ECPubKey): Promise<boolean>;
}

class SeedImple implements SeedDeriver, SeedNavigator {
  constructor(private seeds: { s?: Uint8Array; eprivk?: ECPrivKey }[] = []) {}

  async startKeyAgreement(): Promise<ECPubKey> {
    const sk_api = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    if (!sk_api.publicKey || !sk_api.privateKey) {
      throw new TypeError('Extractive になっていない');
    }
    const sk = await window.crypto.subtle.exportKey('jwk', sk_api.privateKey);
    const pk = await window.crypto.subtle.exportKey('jwk', sk_api.publicKey);
    this.seeds.push({ eprivk: ECPrivKey.fromJWK(sk as ECPirvJWK) });
    return ECPubKey.fromJWK(pk as ECPubJWK);
  }

  async agree(received: ECPubKey): Promise<boolean> {
    try {
      const pub_api = await window.crypto.subtle.importKey(
        'jwk',
        received.toJWK(),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
      );
      const pop = this.seeds.pop();
      if (!pop) {
        throw new RangeError(`Seed 共有を始めていない`);
      }
      const { s, eprivk } = pop;
      if (!eprivk || s) {
        throw new EvalError(`有効でないSeed の共有`);
      }
      const priv_api = await window.crypto.subtle.importKey(
        'jwk',
        eprivk.toJWK(),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits']
      );
      const seed = await window.crypto.subtle.deriveBits(
        { name: 'ECDH', public: pub_api },
        priv_api,
        256
      );
      this.seeds.push({ s: new Uint8Array(seed) });
      return true;
    } catch (e) {
      console.log(e);
      return false;
    }
  }

  private get seed(): Uint8Array {
    if (this.seeds.length != 1) {
      throw new RangeError('Seed を一意に識別できなかった');
    }
    const { s } = this.seeds[0];
    if (!s) {
      throw new EvalError(`Seed が有効でない`);
    }
    return s;
  }

  private async OVK(r: Uint8Array): Promise<ECPrivKey> {
    const d = await kdf(this.seed, r, 256);
    const kid = new KID(BASE64URL(r));
    const pk = new ec('p256').keyFromPrivate(d);
    return ECPrivKey.fromECKeyPair(pk, kid);
  }

  async deriveOVK(r: Uint8Array): Promise<ECPubKey> {
    const sk = await this.OVK(r);
    return sk.toECPubKey();
  }

  async macOVK(x: ECPubKey | Uint8Array, svcID: string): Promise<Uint8Array> {
    let r: Uint8Array;
    if (ECPubKey.is(x)) {
      r = BASE64URL_DECODE(x.kid.kid);
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
    const r = BASE64URL_DECODE(OVK.kid.kid);
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
      r = BASE64URL_DECODE(x.kid.kid);
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
