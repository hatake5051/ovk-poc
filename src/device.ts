import { ECPirvJWK, ECPrivKey, ECPubJWK, ECPubKey, equalECPubJWK } from 'key';
import { Seed } from 'seed';
import {
  BASE64URL,
  BASE64URL_DECODE,
  CONCAT,
  PBES2JWE,
  RandUint8Array,
  UTF8,
  UTF8_DECODE,
} from 'utility';

export class Device {
  private constructor(
    private name: string,
    private seed: Seed,
    private attsKey: ECPrivKey,
    private creds: ECPirvJWK[] = [],
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

  static async gen(name: string, seed: Seed): Promise<Device> {
    return new Device(name, seed, await ECPrivKey.gen());
  }

  async initSeedNegotiation(
    pw: string,
    devID: string,
    partnerID: string,
    devNum: number,
    updating = false
  ): Promise<string> {
    this.negotiating = { pw, devID, devNum, partnerID, epk: { mine: {}, partner: {} } };
    const { epk } = await this.seed.negotiate(
      { id: devID, partnerID, devNum },
      undefined,
      updating
    );
    const m = UTF8(this.negotiating.devID + '.' + JSON.stringify(epk));
    return PBES2JWE.compact(this.negotiating.pw, m);
  }

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
    // クレデンシャルの生成とアテステーション
    const cred_sk = await ECPrivKey.gen();
    const cred_pk_jwk = await (await cred_sk.toECPubKey()).toJWK();
    const sig_atts = await this.attsKey.sign(
      CONCAT(BASE64URL_DECODE(svc.challenge_b64u), UTF8(JSON.stringify(cred_pk_jwk)))
    );
    this.creds.push(await cred_sk.toJWK());
    // 登録するクレデンシャルとアテステーションのセット
    const cred = {
      jwk: cred_pk_jwk,
      atts: { sig_b64u: BASE64URL(sig_atts), key: await (await this.attsKey.toECPubKey()).toJWK() },
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
        ovkm: { ovk_jwk: await ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
      };
    }
  }

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
    const cred_jwk = await (await sk.toECPubKey()).toJWK();
    const sig = await sk.sign(BASE64URL_DECODE(svc.challenge_b64u));
    const sig_b64u = BASE64URL(sig);
    // シードの更新が行われ、 OVK を更新する必要があるか確認する
    if (!(await this.seed.isUpdating())) {
      // updating する必要はないので送信
      return { cred_jwk, sig_b64u };
    }
    // このデバイスにあるシードから導出できる OVK を探す
    const ovkm_correct = await (async (nexts) => {
      if (!nexts) {
        return undefined;
      }
      for (const ovkm_i of nexts) {
        const isVerified = await this.seed.verifyOVK(
          BASE64URL_DECODE(ovkm_i.r_b64u),
          svc.id,
          BASE64URL_DECODE(ovkm_i.mac_b64u)
        );
        if (isVerified) {
          return ovkm_i;
        }
      }
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
          ovkm: { ovk_jwk: await ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
        },
      };
    }
  }
}
