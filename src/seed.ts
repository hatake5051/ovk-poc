import { ECPirvJWK, ECPrivKey, ECPubJWK, ECPubKey } from 'key';
import { BASE64URL_DECODE, CONCAT, UTF8 } from 'utility';

export type Seed = SeedDeriver & SeedNegotiator & SeedUpdater;

export function newSeed(): Seed {
  return new SeedImple();
}

/**
 * SeedDeriver はシードから Ownership Verification Key を導出する機能
 */
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

/**
 * SeedNegotiator はシードを他のデバイスとネゴシエートして同一シードを共有する機能
 */
interface SeedNegotiator {
  /**
   * 他のデバイスと同一シードを共有するために DH 鍵共有を複数デバイスと行う。
   * ３台以上の場合は、何度かデバイス同士でインタラクションする。
   * @param meta ネゴシエートする際に一時的に利用するデバイスの識別子に関する情報。
   * @param epk ネゴシエート中に公開された DH 公開鍵
   * @param update シードの更新を行う場合、true にする（シードを複数持つことができる)
   * @returns completion はこのデバイスのシード計算が終了したことを表す。
   * epk は公開する DH 公開鍵情報
   */
  negotiate(
    meta: { id: string; devIDs: string[] },
    epk?: Record<string, Record<number, ECPubJWK | undefined> | undefined>,
    update?: boolean
  ): Promise<{
    completion: boolean;
    epk: Record<number, ECPubJWK | undefined>;
  }>;
}

interface SeedUpdater {
  isUpdating(): Promise<boolean>;
  update(prevR: Uint8Array, nextOVK: ECPubKey): Promise<Uint8Array>;
}

class SeedImple implements SeedDeriver, SeedNegotiator, SeedUpdater {
  constructor(
    private seeds: Uint8Array[] = [],
    private e?: {
      meta: { id: string; devIDs: string[]; partnerID: string };
      sk: ECPirvJWK;
      idx: number;
    }
  ) {}

  async negotiate(
    meta: { id: string; devIDs: string[] },
    epk?: Record<string, Record<number, ECPubJWK | undefined> | undefined>,
    update = false
  ): Promise<{
    completion: boolean;
    epk: Record<number, ECPubJWK | undefined>;
  }> {
    // Updating かどうか、その場合のすでに所有済みのシードの一人の整合性をチェック
    if ((update && this.seeds.length === 0) || (!update && this.seeds.length !== 0)) {
      // updating 出ない時はシードを保有していないはずで、updating の時はシードを持っているはず
      throw new EvalError(`シードのネゴシエートを始める状態ではない`);
    }
    // ネゴシエート用の ephemeral data を用意する。ネゴシエートの途中ですでに生成済みならそれを使用し、なければ生成する。
    let e = this.e;
    if (e) {
      // すでにネゴシエータようのデータがあれば、 meta data が一致するかチェック
      if (
        e.meta.id !== meta.id ||
        !(
          e.meta.devIDs.every((id) => meta.devIDs.includes(id)) &&
          meta.devIDs.every((id) => e?.meta.devIDs.includes(id))
        )
      ) {
        // meta data はネゴシエートに参加するデバイスの一時的な識別子
        throw new EvalError(`シードのネゴシエート中に違うメタデータを使用している`);
      }
    } else {
      // meta データには複数 DH を行う際の相方情報を含める
      // device List をソートして相方のデバイスを決める (インデックスが一つ前のデバイス);
      const devList = meta.devIDs.includes(meta.id) ? [...meta.devIDs] : [...meta.devIDs, meta.id];
      devList.sort();
      const partner_idx = devList.indexOf(meta.id);
      const partnerID = devList[partner_idx === 0 ? devList.length - 1 : partner_idx - 1];
      this.e = {
        sk: await (await ECPrivKey.gen()).toJWK(),
        meta: { ...meta, partnerID },
        idx: this.seeds.length,
      };
      e = this.e;
    }

    const sk = ECPrivKey.fromJWK(e.sk);
    // このデバイスで生成する DH 公開鍵。 0 step は対応する公開鍵そのもの
    const ans: Record<number, ECPubJWK | undefined> = { 0: await (await sk.toECPubKey()).toJWK() };
    // ネゴシエートする
    if (epk) {
      // 相方のデバイスから出てきた epk に自身の sk で DH していく
      const epk_cp = epk[e.meta.partnerID];
      if (epk_cp) {
        // ３台以上のデバイスの場合は複数回 DH を繰り返してうまいことする
        for (const [cs, pk] of Object.entries(epk_cp)) {
          if (!pk) {
            continue;
          }
          const c = parseInt(cs);
          // c が devNum - 2  より小さい時は DH の結果を他のデバイスに提供する
          if (c < meta.devIDs.length - 2) {
            // すでに計算済みかチェック
            const x = epk[meta.id];
            if (!x || !x[c + 1]) {
              ans[c + 1] = await sk.computeDH(pk);
            }
          } else {
            // デバイスの数 -1 の時は DH の結果がシードの値になる。
            this.seeds.push(BASE64URL_DECODE((await sk.computeDH(pk)).x));
          }
        }
      }

      // 自身のデバイスで DH をこれ以上する必要があるかチェックする
      // 今回計算した DH
      const computed = [...Object.keys(ans)];
      // 以前に計算していた DH
      const x = epk[meta.id];
      if (x) {
        computed.push(...Object.keys(x));
      }
      // 最後の１ step の DH をしているか
      if (this.seeds.length === e.idx + 1) {
        computed.push(`${meta.devIDs.length - 1}`);
      }
      // 全てのステップで計算が完了していれば ephemeral data を破棄する
      if (new Set(computed).size === meta.devIDs.length) {
        this.e = undefined;
      }
    }
    return {
      completion: this.e == null,
      epk: ans,
    };
  }

  private get seed(): Uint8Array {
    if (this.seeds.length == 0) {
      throw new EvalError(`Seed を保有していない`);
    }
    return this.seeds[this.seeds.length - 1];
  }

  private async OVK(r: Uint8Array, s?: Uint8Array): Promise<ECPrivKey> {
    const d = await kdf(s ?? this.seed, r, 256);
    return ECPrivKey.fromSecret(d);
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
      await sk.toJWK(),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    const sig = await window.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, sk_api, cred);
    return new Uint8Array(sig);
  }

  async isUpdating(): Promise<boolean> {
    return this.seeds.length > 1;
  }

  async update(prevR: Uint8Array, nextOVK: ECPubKey): Promise<Uint8Array> {
    if (!(await this.isUpdating())) {
      throw new EvalError(`Migrating 中ではない`);
    }
    const s = this.seeds[this.seeds.length - 2];
    if (!s) {
      throw new EvalError(`Seed が有効でない`);
    }
    const prevSK = await this.OVK(prevR, s);
    const sk_api = await window.crypto.subtle.importKey(
      'jwk',
      await prevSK.toJWK(),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
    const sig = await window.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      sk_api,
      UTF8(JSON.stringify(await nextOVK.toJWK()))
    );
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
