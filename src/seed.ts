import { ECPirvJWK, ECPrivKey, ECPubJWK, ECPubKey } from 'key';
import { BASE64URL_DECODE, CONCAT, HKDF, HMAC, UTF8 } from 'utility';

export type Seed = SeedDeriver & SeedNegotiator & SeedUpdater;

export function newSeed(): Seed {
  return new SeedImpl();
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
   * @param r OVK を導出する際に用いた乱数
   * @param svcID 登録先のサービス識別子 (dns 名)
   * @returns OVK の秘密鍵で (r || UTF8(svcID)) に対して計算した MAC
   */
  macOVK(r: Uint8Array, svcID: string): Promise<Uint8Array>;
  /**
   * OVK がこのサービスのために他のデバイスで生成されたかを MAC を用いて検証する。
   * @param r OVK を導出するために用いた乱数
   * @param svcID 登録先のサービス識別子 (dns 名)
   * @param MAC サービスから取得した MAC
   * @returns 検証に成功すれば true
   */
  verifyOVK(r: Uint8Array, svcID: string, MAC: Uint8Array): Promise<boolean>;
  /**
   * OVK を用いてクレデンシャルに署名する。
   * @param r OVK を導出する際に用いた乱数
   * @param cred OVPrivK が署名するクレデンシャル
   * @returns OVK の秘密鍵で cred に対して計算した署名
   */
  signOVK(r: Uint8Array, cred: Uint8Array): Promise<Uint8Array>;
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
    meta: { id: string; partnerID: string; devNum: number },
    epk?: {
      mine?: Record<number, ECPubJWK | undefined>;
      partner?: Record<number, ECPubJWK | undefined>;
    },
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

class SeedImpl implements SeedDeriver, SeedNegotiator, SeedUpdater {
  constructor(
    private seeds: Uint8Array[] = [],
    private e?: {
      meta: { id: string; partnerID: string; devNum: number };
      sk: ECPirvJWK;
      idx: number;
    }
  ) {}

  async negotiate(
    meta: { id: string; partnerID: string; devNum: number },
    epk?: {
      mine?: Record<number, ECPubJWK | undefined>;
      partner?: Record<number, ECPubJWK | undefined>;
    },
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
        e.meta.partnerID !== meta.partnerID ||
        e.meta.devNum !== meta.devNum
      ) {
        // meta data はネゴシエートに参加するデバイスの一時的な識別子
        throw new EvalError(`シードのネゴシエート中に違うメタデータを使用している`);
      }
    } else {
      this.e = {
        sk: (await ECPrivKey.gen()).toJWK(),
        meta,
        idx: this.seeds.length,
      };
      e = this.e;
    }

    const sk = await ECPrivKey.fromJWK(e.sk);
    // このデバイスで生成する DH 公開鍵。 0 step は対応する公開鍵そのもの
    const ans: Record<number, ECPubJWK | undefined> = { 0: sk.toECPubKey().toJWK() };
    // ネゴシエートする
    if (epk) {
      // 相方のデバイスから出てきた epk に自身の sk で DH していく
      if (epk.partner) {
        // ３台以上のデバイスの場合は複数回 DH を繰り返してうまいことする
        for (const [cs, pk] of Object.entries(epk.partner)) {
          if (!pk) {
            continue;
          }
          const c = parseInt(cs);
          // c が devNum - 2  より小さい時は DH の結果を他のデバイスに提供する
          if (c < meta.devNum - 2) {
            // すでに計算済みかチェック
            if (!epk.mine || !epk.mine[c + 1]) {
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
      if (epk.mine) {
        computed.push(...Object.keys(epk.mine));
      }
      // 最後の１ step の DH をしているか
      if (this.seeds.length === e.idx + 1) {
        computed.push(`${meta.devNum - 1}`);
      }
      // 全てのステップで計算が完了していれば ephemeral data を破棄する
      if (new Set(computed).size === meta.devNum) {
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
    const d = await HKDF(s ?? this.seed, r, 256);
    return ECPrivKey.fromSecret(d);
  }

  async deriveOVK(r: Uint8Array): Promise<ECPubKey> {
    const sk = await this.OVK(r);
    return sk.toECPubKey();
  }

  async macOVK(r: Uint8Array, svcID: string): Promise<Uint8Array> {
    const sk = await this.OVK(r);
    return await HMAC.mac(sk.d('oct'), CONCAT(r, UTF8(svcID)));
  }

  async verifyOVK(r: Uint8Array, svcID: string, MAC: Uint8Array): Promise<boolean> {
    const sk = await this.OVK(r);
    return await HMAC.verify(sk.d('oct'), CONCAT(r, UTF8(svcID)), MAC);
  }

  async signOVK(r: Uint8Array, cred: Uint8Array): Promise<Uint8Array> {
    const sk = await this.OVK(r);
    return await sk.sign(cred);
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
    const sig = await prevSK.sign(UTF8(JSON.stringify(nextOVK.toJWK())));
    return new Uint8Array(sig);
  }
}
