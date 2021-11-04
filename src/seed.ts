import { ec } from 'elliptic';
import { ECPrivKey, ECPubKey, KID } from 'key';
import { CONCAT, UTF8 } from 'utility';

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
