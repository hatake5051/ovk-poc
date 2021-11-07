import { ECPubJWK, equalECPubJWK } from 'key';
import { BASE64URL, BASE64URL_DECODE, UTF8 } from 'utility';

export function newService(id: string): Service {
  return new Service(id);
}

export class Service {
  private db: Record<string, CredManager | undefined>;
  private challengeDB: Record<string, string | undefined>;
  constructor(private id: string) {
    this.db = {};
    this.challengeDB = {};
  }

  async register(
    name: string,
    creds_utf8: string,
    ovkm: {
      ovk_jwk: ECPubJWK;
      r_b64u: string;
      mac_b64u: string;
    }
  ): Promise<boolean> {
    try {
      const cm = CredManager.init(creds_utf8, ovkm);
      this.db[name] = cm;
      return true;
    } catch (e) {
      return false;
    }
  }

  async startAuthn(name: string): Promise<{
    challenge_b64u: string;
    creds_utf8: string[];
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
  }> {
    const cm = this.db[name];
    if (!cm) {
      throw new EvalError(`未登録ユーザです`);
    }
    const challenge = window.crypto.getRandomValues(new Uint8Array(32));
    this.challengeDB[name] = BASE64URL(challenge);
    return { challenge_b64u: BASE64URL(challenge), ...cm.getCreds() };
  }

  async seamlessRegister(
    name: string,
    cred_utf8: string,
    sig_b64u: string,
    ov: {
      sig_b64u: string;
    }
  ): Promise<boolean> {
    const cm = this.db[name];
    if (!cm) {
      return false;
    }
    const ovk_jwk = cm.getOVK();
    const pk_api = await window.crypto.subtle.importKey(
      'jwk',
      ovk_jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    if (
      !(await window.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pk_api,
        BASE64URL_DECODE(ov.sig_b64u),
        UTF8(cred_utf8)
      ))
    ) {
      return false;
    }
    if (!cm.add(cred_utf8, ovk_jwk)) {
      return false;
    }
    return this.authn(name, cred_utf8, sig_b64u);
  }

  async authn(
    name: string,
    cred_utf8: string,
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
    const challenge_b64u = this.challengeDB[name];
    if (!challenge_b64u) {
      return false;
    }
    this.challengeDB[name] = undefined;
    const cm = this.db[name];
    if (!cm || !cm.isCred(cred_utf8)) {
      return false;
    }
    const key = await window.crypto.subtle.importKey(
      'raw',
      UTF8(cred_utf8),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    return await window.crypto.subtle.verify(
      'HMAC',
      key,
      BASE64URL_DECODE(sig_b64u),
      BASE64URL_DECODE(challenge_b64u)
    );
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
    const ovk_jwk = cm.getOVK();
    const pk_api = await window.crypto.subtle.importKey(
      'jwk',
      ovk_jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    if (
      !(await window.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pk_api,
        BASE64URL_DECODE(update_b64u),
        UTF8(JSON.stringify(ovkm_next.ovk_jwk))
      ))
    ) {
      return false;
    }
    return cm.addUpdating(ovkm_next.ovk_jwk, ovkm_next.r_b64u, ovkm_next.mac_b64u);
  }
}

class CredManager {
  private constructor(
    private creds_utf8: Record<string, ECPubJWK>,
    private ovkm: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string },
    private next?: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string }[]
  ) {}

  static init(
    cred_utf8: string,
    ovkm: {
      ovk_jwk: ECPubJWK;
      r_b64u: string;
      mac_b64u: string;
    }
  ): CredManager {
    return new CredManager({ [cred_utf8]: ovkm.ovk_jwk }, ovkm);
  }

  add(cred_utf8: string, ovk_jwk: ECPubJWK): boolean {
    this.creds_utf8[cred_utf8] = ovk_jwk;
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
    creds_utf8: string[];
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
      creds_utf8: Object.keys(this.creds_utf8),
      ovkm: {
        ovk_jwk: this.ovkm.ovk_jwk,
        r_b64u: this.ovkm.r_b64u,
        mac_b64u: this.ovkm.mac_b64u,
        next: this.next,
      },
    };
  }
  isCred(cred_utf8: string): boolean {
    return Object.keys(this.creds_utf8).some((c) => c === cred_utf8);
  }
  getOVK(): ECPubJWK {
    return this.ovkm.ovk_jwk;
  }
}
