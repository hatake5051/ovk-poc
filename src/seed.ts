import { ec } from 'elliptic';
import { ECPirvJWK, ECPrivKey, ECPubJWK, ECPubKey, KID } from 'key';
import { BASE64URL, CONCAT, UTF8 } from 'utility';

export type Seed = SeedDeriver & SeedNavigator;

export function newSeed(): Seed {
  return new SeedImple();
}

interface SeedDeriver {
  /**
   * 乱数とシードから Ownership Verification Key を導出する。
   * @param r 乱数
   * @returns Ownership Verification Public Key
   */
  deriveOVK(r: Uint8Array): Promise<ECPubKey>;
  /**
   * OVK を特定のサービスに対して生成したことを検証できる MAC を計算する。
   * @param OVK  Ownership Verification Public Key でこれに対応する秘密鍵をシードは内部で識別できる。
   * @param r OVK を導出する際に用いた乱数
   * @param svcID 登録先のサービス識別子 (dns 名)
   * @returns OVK の秘密鍵で (r || UTF8(svcID)) に対して計算した MAC
   */
  macOVK(OVK: ECPubKey, r: Uint8Array, svcID: string): Promise<Uint8Array>;
  /**
   * OVK がこのサービスのために他のデバイスで生成されたかを MAC を用いて検証する。
   * @param OVK Ownership Verification Public Key でこれに対応する秘密鍵をシードは内部で識別できる。
   * @param r OVK を導出するために用いた乱数
   * @param svcID 登録先のサービス識別子 (dns 名)
   * @param MAC サービスから取得した MAC
   * @returns 検証に成功すれば true
   */
  verifyOVK(OVK: ECPubKey, r: Uint8Array, svcID: string, MAC: Uint8Array): Promise<boolean>;
  /**
   * OVK を用いてクレデンシャルに署名する。
   * @param OVK OVPubK でこれに対応する秘密鍵をシードは内部で識別できる。
   * @param r OVK を導出する際に用いた乱数
   * @param cred OVPrivK が署名するクレデンシャル
   * @returns OVK の秘密鍵で cred に対して計算した署名
   */
  signOVK(OVK: ECPubKey, r: Uint8Array, cred: Uint8Array): Promise<Uint8Array>;
}

interface SeedNavigator {
  startAgreement(update?: boolean): Promise<ECPubKey>;
  agree(received: ECPubKey): Promise<boolean>;
}

class SeedImple implements SeedDeriver, SeedNavigator {
  constructor(private seeds: { s?: Uint8Array; eprivk?: ECPrivKey }[] = []) {}

  async startAgreement(update = false): Promise<ECPubKey> {
    if (!update && this.seeds.length != 0) {
      throw new EvalError('シードをすでに保持している');
    }
    if (update && this.seeds.length != 1) {
      throw new EvalError('シードの更新を始められない');
    }
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
        this.seeds.push(pop);
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

  async macOVK(OVK: ECPubKey, r: Uint8Array, svcID: string): Promise<Uint8Array> {
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

  async verifyOVK(OVK: ECPubKey, r: Uint8Array, svcID: string, MAC: Uint8Array): Promise<boolean> {
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

  async signOVK(OVK: ECPubKey, r: Uint8Array, cred: Uint8Array): Promise<Uint8Array> {
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
