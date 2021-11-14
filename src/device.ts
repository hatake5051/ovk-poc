import { ECPirvJWK, ECPrivKey, ECPubJWK, ECPubKey, equalECPubJWK } from 'key';
import { Seed } from 'seed';
import { BASE64URL, BASE64URL_DECODE, CONCAT, UTF8, UTF8_DECODE } from 'utility';
import { PBES2JWE, RandUint8Array } from 'utility/crypto';

/**
 * シードを管理できて、鍵管理を行える認証器
 */
export class Device {
  private constructor(
    /**
     * デバイス名
     */
    private name: string,
    /**
     * Seed 機能
     */
    private seed: Seed,
    /**
     * このデバイスのアテステーションキー
     */
    private attsKey: ECPrivKey,
    /**
     * このデバイスのクレデンシャル
     */
    private creds: ECPirvJWK[] = [],
    /**
     * シードネゴシエーション中の情報
     */
    private negotiating?: {
      pw: string;
      devID: string;
      partnerID: string;
      devNum: number;
      epk: {
        mine: Record<number, ECPubJWK | undefined>;
        partner: Record<number, ECPubJWK | undefined>;
      };
    }
  ) {}

  /**
   * デバイスを作成する
   * @param name デバイス名
   * @param seed シード管理機能
   */
  static async gen(name: string, seed: Seed): Promise<Device> {
    return new Device(name, seed, await ECPrivKey.gen());
  }

  /**
   * シードネゴシエーションを開始する。
   * @param pw シード共有時のパスワード
   * @param devID 自身のデバイス識別子
   * @param partnerID 共有時の情報を受け取る相手のデバイス識別子
   * @param devNum 共有に参加するデバイスの総数
   * @param updating シードの更新を行おうとしているかどうか
   * @returns シードネゴシエーションするための情報
   */
  async initSeedNegotiation(
    pw: string,
    devID: string,
    partnerID: string,
    devNum: number,
    updating = false
  ): Promise<string> {
    // ネゴシエーション中の情報を一時的に保存して
    this.negotiating = { pw, devID, devNum, partnerID, epk: { mine: {}, partner: {} } };
    // ネゴシエーション１回め
    const { epk } = await this.seed.negotiate(
      { id: devID, partnerID, devNum },
      undefined,
      updating
    );
    // ネゴシエーション用の情報を作成したデバイスを識別するための情報に載せて
    const m = UTF8(this.negotiating.devID + '.' + JSON.stringify(epk));
    // パスワードで暗号化
    return PBES2JWE.compact(this.negotiating.pw, m);
  }

  /**
   * 他のデバイスから情報をもらってシードネゴシエートする。
   * @param ciphertext 他のデバイスから届いたネゴシエーション中の情報
   * @param updating シードの更新を行なっている最中かどうか
   * @returns 計算結果
   */
  async seedNegotiating(
    ciphertext: string,
    updating = false
  ): Promise<{ completion: boolean; ciphertext: string }> {
    if (!this.negotiating) {
      throw new EvalError(`シードのネゴシエーション初期化を行っていない`);
    }

    let m_received: Uint8Array;
    try {
      m_received = await PBES2JWE.dec(this.negotiating.pw, ciphertext);
    } catch {
      throw new EvalError(`Ciphertext の復号に失敗`);
    }
    const l = UTF8_DECODE(m_received).split('.');
    if (l.length !== 2) {
      throw new EvalError(`message フォーマットエラー`);
    }
    const [devID_received, epk_received] = l;
    if (devID_received === this.negotiating.partnerID) {
      Object.assign(this.negotiating.epk.partner, JSON.parse(epk_received));
    }

    const { completion, epk: epk_computed } = await this.seed.negotiate(
      {
        id: this.negotiating.devID,
        partnerID: this.negotiating.partnerID,
        devNum: this.negotiating.devNum,
      },
      this.negotiating.epk,
      updating
    );
    Object.assign(this.negotiating.epk.mine, epk_computed);
    const m_computed = UTF8(
      this.negotiating.devID + '.' + JSON.stringify(this.negotiating.epk.mine)
    );
    const ciphertext_ans = await PBES2JWE.compact(this.negotiating.pw, m_computed);

    if (completion) {
      this.negotiating = undefined;
    }
    return { completion, ciphertext: ciphertext_ans };
  }

  /**
   * サービスに登録する。
   * @param svc 登録先のサービス識別子 とチャレンジ
   * @param ovkm 登録先のサービスから Ownership verification key material があれば
   * @returns 登録するための情報
   */
  async register(
    svc: { id: string; challenge_b64u: string },
    ovkm?: { r_b64u: string; mac_b64u: string }
  ): Promise<{
    cred: {
      jwk: ECPubJWK;
      atts: { sig_b64u: string; key: ECPubJWK };
    };
    ovkm: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string } | { sig_b64u: string };
  }> {
    // クレデンシャルの生成とアテステーションを行う
    const cred_sk = await ECPrivKey.gen();
    const cred_pk_jwk = cred_sk.toECPubKey().toJWK();
    const sig_atts = await this.attsKey.sign(
      CONCAT(BASE64URL_DECODE(svc.challenge_b64u), UTF8(JSON.stringify(cred_pk_jwk)))
    );
    this.creds.push(cred_sk.toJWK());
    // 登録するクレデンシャルとアテステーションのセット
    const cred = {
      jwk: cred_pk_jwk,
      atts: { sig_b64u: BASE64URL(sig_atts), key: this.attsKey.toECPubKey().toJWK() },
    };
    if (ovkm) {
      // 他のデバイスで OVK 登録済みなので、シームレスな登録を行う
      const r = BASE64URL_DECODE(ovkm.r_b64u);
      const mac = BASE64URL_DECODE(ovkm.mac_b64u);
      if (!(await this.seed.verifyOVK(r, svc.id, mac))) {
        throw new EvalError(`OVKの検証に失敗`);
      }
      const sig_ovk = await this.seed.signOVK(r, UTF8(JSON.stringify(cred_pk_jwk)));
      return { cred, ovkm: { sig_b64u: BASE64URL(sig_ovk) } };
    } else {
      // クレデンシャルとともに OVK を登録する
      const r = RandUint8Array(16);
      const ovk = await this.seed.deriveOVK(r);
      const mac = await this.seed.macOVK(r, svc.id);
      return {
        cred,
        ovkm: { ovk_jwk: ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
      };
    }
  }

  /**
   *
   * @param svc サービス識別子とチャレンジと登録済みクレデンシャル
   * @param ovkm Ownership Verification Key Material があれば
   * @returns 認証するための情報
   */
  async authn(
    svc: { id: string; challenge_b64u: string; creds: ECPubJWK[] },
    ovkm: {
      r_b64u: string;
      mac_b64u: string;
      next?: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string }[];
    }
  ): Promise<{
    cred_jwk: ECPubJWK;
    sig_b64u: string;
    updating?: {
      update_b64u: string;
      ovkm: {
        ovk_jwk: ECPubJWK;
        r_b64u: string;
        mac_b64u: string;
      };
    };
  }> {
    // 登録済みのクレデンシャルから対応する秘密鍵を識別する
    const cred_sk = this.creds.find((sk) => svc.creds.some((pk) => equalECPubJWK(pk, sk)));
    if (!cred_sk) {
      throw new EvalError(`登録済みのクレデンシャルはこのデバイスにない`);
    }
    // challenge に署名する
    const sk = await ECPrivKey.fromJWK(cred_sk);
    const cred_jwk = sk.toECPubKey().toJWK();
    const sig = await sk.sign(BASE64URL_DECODE(svc.challenge_b64u));
    const sig_b64u = BASE64URL(sig);
    // シードの更新が行われ、 OVK を更新する必要があるか確認する
    // updating 中でないなら、もしくは updating 中だが OVK の更新が終了していれば update メッセージを送らない
    if (
      !(await this.seed.isUpdating()) ||
      (await this.seed.verifyOVK(
        BASE64URL_DECODE(ovkm.r_b64u),
        svc.id,
        BASE64URL_DECODE(ovkm.mac_b64u)
      ))
    ) {
      // updating する必要はないので送信
      return { cred_jwk, sig_b64u };
    }

    // シードの更新が行われているので、 OVK を更新する
    // このデバイスにあるシードから導出できる OVK を探す
    const ovkm_correct = await (async (nexts) => {
      if (!nexts) {
        // どのでばいすも update メッセージを送っていない
        return undefined;
      }
      for (const ovkm_i of nexts) {
        // OVK の検証に成功すれば、それが同じシードを持つ別のデバイスで生成された OVK
        const isVerified = await this.seed.verifyOVK(
          BASE64URL_DECODE(ovkm_i.r_b64u),
          svc.id,
          BASE64URL_DECODE(ovkm_i.mac_b64u)
        );
        if (isVerified) {
          return ovkm_i;
        }
      }
      // update メッセージは登録されているが、同じシードを持つデバイスからのものではない
      return undefined;
    })(ovkm.next);

    if (ovkm_correct) {
      // すでに登録済みの nextOVK に対応する Update メッセージを送る
      const update = await this.seed.update(
        BASE64URL_DECODE(ovkm.r_b64u),
        await ECPubKey.fromJWK(ovkm_correct.ovk_jwk)
      );
      return {
        cred_jwk,
        sig_b64u,
        updating: {
          update_b64u: BASE64URL(update),
          ovkm: ovkm_correct,
        },
      };
    } else {
      // どのデバイスでも Update メッセージを送っていない もしくは
      // Update メッセージを全て検証できていない -> 攻撃者が update メッセージ送信している...
      const r = RandUint8Array(16);
      const ovk = await this.seed.deriveOVK(r);
      const mac = await this.seed.macOVK(r, svc.id);
      const update = await this.seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
      return {
        cred_jwk,
        sig_b64u,
        updating: {
          update_b64u: BASE64URL(update),
          ovkm: { ovk_jwk: ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
        },
      };
    }
  }
}
