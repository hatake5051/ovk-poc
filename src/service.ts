import { ECPubJWK, ECPubKey, equalECPubJWK } from 'key';
import { BASE64URL, BASE64URL_DECODE, CONCAT, UTF8 } from 'utility';
import { RandUint8Array } from 'utility/crypto';

export function newService(id: string): Service {
  return new Service(id);
}

export class Service {
  private db: Record<string, CredManager | undefined>;
  private challengeDB: Record<string, string[]>;
  constructor(private id: string) {
    this.db = {};
    this.challengeDB = {};
  }

  async startAuthn(name: string): Promise<
    | { challenge_b64u: string }
    | {
        challenge_b64u: string;
        creds: ECPubJWK[];
        ovkm: {
          ovk_jwk: ECPubJWK;
          r_b64u: string;
          mac_b64u: string;
          next?: {
            ovk_jwk: ECPubJWK;
            r_b64u: string;
            mac_b64u: string;
          }[];
        };
      }
  > {
    const challenge = RandUint8Array(32);
    this.challengeDB[name] = [BASE64URL(challenge)];
    const cm = this.db[name];
    if (!cm) {
      return { challenge_b64u: BASE64URL(challenge) };
    }
    return { challenge_b64u: BASE64URL(challenge), ...cm.getCreds() };
  }

  async register(
    name: string,
    cred: {
      jwk: ECPubJWK;
      atts: { sig_b64u: string; key: ECPubJWK };
    },
    ovkm: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string } | { sig_b64u: string }
  ): Promise<boolean> {
    const challenge_b64u = this.challengeDB[name].pop();
    if (!challenge_b64u) {
      return false;
    }
    // cred のアテステーションを検証する.
    // 面倒なので アテステーションキーの検証は考慮していない
    const pk_atts = await ECPubKey.fromJWK(cred.atts.key);
    if (
      !(await pk_atts.verify(
        CONCAT(BASE64URL_DECODE(challenge_b64u), UTF8(JSON.stringify(cred.jwk))),
        BASE64URL_DECODE(cred.atts.sig_b64u)
      ))
    ) {
      // アテステーションの検証に失敗
      return false;
    }

    let cm = this.db[name];
    if (!cm) {
      if ('ovk_jwk' in ovkm) {
        // アカウント初期登録
        cm = CredManager.init(cred.jwk, ovkm);
        this.db[name] = cm;
        return true;
      } else {
        // アカウント新規登録なのに OVK を利用したクレデンシャルの登録をしようとしている
        return false;
      }
    }
    // アカウントは登録済みなので、 OVK を利用したクレデンシャルの登録を行う
    if ('ovk_jwk' in ovkm) {
      // アカウント登録済みなのに、 OVK を追加登録しようとしている
      return false;
    }
    const ovk = await ECPubKey.fromJWK(cm.getOVK());
    if (!(await ovk.verify(UTF8(JSON.stringify(cred.jwk)), BASE64URL_DECODE(ovkm.sig_b64u)))) {
      // OVK を使ってクレデンシャルの検証に失敗
      return false;
    }
    return cm.add(cred.jwk);
  }

  async authn(
    name: string,
    cred_jwk: ECPubJWK,
    sig_b64u: string,
    updating?: {
      update_b64u: string;
      ovkm: {
        ovk_jwk: ECPubJWK;
        r_b64u: string;
        mac_b64u: string;
      };
    }
  ): Promise<boolean> {
    if (updating) {
      if (!(await this.update(name, updating.update_b64u, updating.ovkm))) {
        return false;
      }
    }
    const challenge_b64u = this.challengeDB[name].pop();
    if (!challenge_b64u) {
      return false;
    }
    const cm = this.db[name];
    if (!cm || !cm.isCred(cred_jwk)) {
      return false;
    }
    const cred = await ECPubKey.fromJWK(cred_jwk);
    return cred.verify(BASE64URL_DECODE(challenge_b64u), BASE64URL_DECODE(sig_b64u));
  }

  async update(
    name: string,
    update_b64u: string,
    ovkm_next: {
      ovk_jwk: ECPubJWK;
      r_b64u: string;
      mac_b64u: string;
    }
  ): Promise<boolean> {
    const cm = this.db[name];
    if (!cm) {
      return false;
    }
    const ovk = await ECPubKey.fromJWK(cm.getOVK());
    if (
      !(await ovk.verify(UTF8(JSON.stringify(ovkm_next.ovk_jwk)), BASE64URL_DECODE(update_b64u)))
    ) {
      return false;
    }

    return cm.addUpdating(ovkm_next.ovk_jwk, ovkm_next.r_b64u, ovkm_next.mac_b64u);
  }

  async delete(name: string): Promise<void> {
    this.db[name] = undefined;
    return;
  }
}

class CredManager {
  private constructor(
    private creds: { jwk: ECPubJWK; ovk: ECPubJWK }[],
    private ovkm: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string },
    private next?: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string }[]
  ) {}

  static init(
    cred_jwk: ECPubJWK,
    ovkm: {
      ovk_jwk: ECPubJWK;
      r_b64u: string;
      mac_b64u: string;
    }
  ): CredManager {
    return new CredManager([{ jwk: cred_jwk, ovk: ovkm.ovk_jwk }], ovkm);
  }

  add(cred_jwk: ECPubJWK, ovk_jwk?: ECPubJWK): boolean {
    const ovk = ovk_jwk ?? this.getOVK();
    this.creds.push({ jwk: cred_jwk, ovk });
    return true;
  }

  addUpdating(ovk_jwk: ECPubJWK, r_b64u: string, mac_b64u: string): boolean {
    if (!this.next) {
      this.next = [];
    }
    if (!this.next.some((next) => equalECPubJWK(next.ovk_jwk, ovk_jwk))) {
      this.next.push({ ovk_jwk, r_b64u, mac_b64u });
    }
    return true;
  }

  getCreds(): {
    creds: ECPubJWK[];
    ovkm: {
      ovk_jwk: ECPubJWK;
      r_b64u: string;
      mac_b64u: string;
      next?: {
        ovk_jwk: ECPubJWK;
        r_b64u: string;
        mac_b64u: string;
      }[];
    };
  } {
    return {
      creds: this.creds.map((c) => c.jwk),
      ovkm: {
        ovk_jwk: this.ovkm.ovk_jwk,
        r_b64u: this.ovkm.r_b64u,
        mac_b64u: this.ovkm.mac_b64u,
        next: this.next,
      },
    };
  }
  isCred(cred_jwk: ECPubJWK): boolean {
    return this.creds.some((c) => equalECPubJWK(c.jwk, cred_jwk));
  }
  getOVK(): ECPubJWK {
    return this.ovkm.ovk_jwk;
  }
}
