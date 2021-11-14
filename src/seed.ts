import { ECPirvJWK, ECPrivKey, ECPubJWK, ECPubKey } from 'key';
import { BASE64URL_DECODE, CONCAT, UTF8 } from 'utility';
import { HKDF, HMAC } from 'utility/crypto';

/**
 * Seed はシードを管理する機能を提供する。
 * シードから Ownership Verification Key を導出する SeedDeriver と、
 * シードを他のデバイスと共有する SeedNegotiator と、
 * シードを更新する SeedUpdater からなる。
 */
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
   * HKDF(key: seed, salt: r) で秘密鍵成分を導出し、これから公開鍵を計算する。
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
 * ２つのデバイスA,B でやりとりする場合は、以下のように行われる。
 * 妥当性は sa * epk_b[0] = sa * pb = sb * pa = sb * epk_a[0] だから。
 * 1. A が (sa, pa) の鍵ペアを生成し epk_a = {0: pa} を公開する。
 * 1. B が (sb, pb) の鍵ペアを生成し epk_b = {0: pb} を公開する。
 * 1. A が epk_b を受け取って sa * epk_b[0] を計算し、この x 座標をシードにする。
 * 2. B が epk_a を受け取って sb * epk_a[0] を計算し、この x 座標をシードにする。
 *
 *
 * ３つのデバイス A,B,C でやりとりする場合は、以下のように行われる。
 * 妥当性は以下の３つが同じだから。
 * - sa * epk_c[1] = sa * (sc * epk_b[0]) = sa * (sc * pb)
 * - sb * epk_a[1] = sb * (sa * epk_c[0]) = sb * (sa * pc)
 * - sc * epk_b[1] = sc * (sb * spk_a[1]) = sc * (sb * pa)
 *
 * 1. A,B,C が (sx, px) の鍵ペアを生成し epk_x = {0: px} を公開する。
 * 1. A は C から epk_c を受け取って epk_a = {0: pa, 1: sa * epk_c[0]} を公開する。
 * 1. B は A から epk_a を受け取って epk_b = {0: pb, 1: sb * epk_a[0]} を公開し、 sb * epk_a[1] の x 座標をシードにする。
 * 1. C は B から epk_b を受け取って epk_c = {0: pc, 1: sc * epk_b[0]} を公開し、 sc * epk_b[1] の x 座標をシードにする。
 * 1. A は C から epk_c を受け取って sa * epk_c[1] の x 座標をシードにする。
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

/**
 * SeedUpdater はシードの更新を行う機能を持つ。更新する際の共有は SeedNegotiator で行う。
 */
interface SeedUpdater {
  /**
   * isUpdating はシードの更新を行なっていれば true を返す。
   */
  isUpdating(): Promise<boolean>;
  /**
   * previous OVK で next OVK の検証鍵に署名した結果を返す。
   * @param prevR 以前登録していた OVK を導出するための乱数 R
   * @param nextOVK シードを更新して新しく使う OVK
   */
  update(prevR: Uint8Array, nextOVK: ECPubKey): Promise<Uint8Array>;
  /**
   * update が完了したことを Seed に伝え、previous シードを破棄する。
   */
  completeUpdation(): Promise<void>;
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

  async completeUpdation(): Promise<void> {
    if (!(await this.isUpdating())) {
      throw new EvalError(`Migrating 中ではない`);
    }
    this.seeds.shift();
    return;
  }
}
