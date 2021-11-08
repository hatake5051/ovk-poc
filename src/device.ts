import { ECPubJWK } from 'key';
import { Seed } from 'seed';
import { ASCII, BASE64URL, BASE64URL_DECODE, CONCAT, UTF8, UTF8_DECODE } from 'utility';

export class Device {
  constructor(
    private seed: Seed,
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

  async initSeedNegotiation(
    pw: string,
    devID: string,
    partnerID: string,
    devNum: number
  ): Promise<string> {
    this.negotiating = { pw, devID, devNum, partnerID, epk: { mine: {}, partner: {} } };
    const { epk } = await this.seed.negotiate({ id: devID, partnerID, devNum });
    const m = UTF8(this.negotiating.devID + '.' + JSON.stringify(epk));
    return PBES2JWE.compact(this.negotiating.pw, m);
  }

  async seedNegotiating(ciphertext: string): Promise<{ completion: boolean; ciphertext: string }> {
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
      this.negotiating.epk
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
}

const PBES2JWE = {
  async compact(pw: string, m: Uint8Array): Promise<string> {
    // PBES2 用の JOSE Header を用意して
    const header = {
      alg: 'PBES2-HS256+A128KW',
      enc: 'A128GCM',
      p2c: 1000,
      p2s: BASE64URL(window.crypto.getRandomValues(new Uint8Array(16))),
    };
    const header_b64u = BASE64URL(UTF8(JSON.stringify(header)));

    // Content Encryption Key を乱数生成する
    const cek = window.crypto.getRandomValues(new Uint8Array(16));
    const cek_api = await window.crypto.subtle.importKey('raw', cek, 'AES-GCM', true, ['encrypt']);
    // CEK を使って m を暗号化
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const e = new Uint8Array(
      await window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: ASCII(header_b64u),
        },
        cek_api,
        m
      )
    );
    const ciphertext = e.slice(0, e.length - 16);
    const atag = e.slice(e.length - 16);

    // PBES2 で導出した鍵で CEK をラップして Encrypted Key を生成する
    const dk_api = await window.crypto.subtle.importKey(
      'raw',
      await window.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
          iterations: header.p2c,
        },
        await window.crypto.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']),
        128
      ),
      { name: 'AES-KW' },
      false,
      ['wrapKey']
    );
    const ek = new Uint8Array(
      await window.crypto.subtle.wrapKey('raw', cek_api, dk_api, { name: 'AES-KW' })
    );
    const ek_b64u = BASE64URL(ek);

    return `${header_b64u}.${ek_b64u}.${BASE64URL(iv)}.${BASE64URL(ciphertext)}.${BASE64URL(atag)}`;
  },

  async dec(pw: string, compact: string): Promise<Uint8Array> {
    const l = compact.split('.');
    if (l.length !== 5) {
      throw new EvalError('JWE Compact Serialization の形式ではない');
    }
    const [h_b64u, ek_b64u, iv_b64u, c_b64u, atag_b64u] = l;
    const header = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(h_b64u)));

    // PBES2 で導出した鍵で EK をアンラップして CEK を得る
    const dk_api = await window.crypto.subtle.importKey(
      'raw',
      await window.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
          iterations: header.p2c,
        },
        await window.crypto.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']),
        128
      ),
      { name: 'AES-KW' },
      false,
      ['unwrapKey']
    );
    const cek_api = await window.crypto.subtle.unwrapKey(
      'raw',
      BASE64URL_DECODE(ek_b64u),
      dk_api,
      {
        name: 'AES-KW',
      },
      'AES-GCM',
      true,
      ['decrypt']
    );
    // CEK を使って ciphertext と authentication tag から平文を復号し整合性を検証する
    const e = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: BASE64URL_DECODE(iv_b64u), additionalData: ASCII(h_b64u) },
      cek_api,
      CONCAT(BASE64URL_DECODE(c_b64u), BASE64URL_DECODE(atag_b64u))
    );
    return new Uint8Array(e);
  },
};
