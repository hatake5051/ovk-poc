import { ECPubJWK, ECPubKey, equalECPubJWK } from 'key';
import { BASE64URL, BASE64URL_DECODE, CONCAT, UTF8 } from 'utility';
import { RandUint8Array } from 'utility/crypto';

// マイグレーション時間は 3分 にしておく
const migrating_date_ms = 3 * 60 * 1000;

/**
 * 認証機能を持つサービスで、 OVK を利用したクレデンシャルの登録に対応している
 */
export class Service {
  /**
   * ユーザとそのクレデンシャルを保持するデータベース
   */
  private db: Record<string, CredManager | undefined>;
  /**
   * ユーザに発行した chellenge を一時的に保存するデータベース
   */
  private challengeDB: Record<string, string[]>;
  private constructor(private id: string) {
    this.db = {};
    this.challengeDB = {};
  }

  /**
   * サービスを作成する
   * @param id サービス識別子
   * @returns サービス
   */
  static gen(id: string): Service {
    return new Service(id);
  }

  /**
   * 認証リクエストを処理する。
   * @param name ユーザ名
   * @returns 登録済みなら登録済みクレデンシャルと ovk を返し、未登録ならチャレンジだけ返す
   */
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
    // チャレンジを生成して、一時的に保存する。
    const challenge = RandUint8Array(32);
    this.challengeDB[name] = [BASE64URL(challenge)];
    const cm = this.db[name];
    if (!cm) {
      // 未登録ユーザなので、 chellenge だけ返す
      return { challenge_b64u: BASE64URL(challenge) };
    }
    // 登録ユーザはクレデンシャル情報を含めて返す
    return { challenge_b64u: BASE64URL(challenge), ...cm.getCreds() };
  }

  /**
   * ユーザを登録する or クレデンシャルを追加する
   * @param name ユーザ名
   * @param cred 登録するクレデンシャル
   * @param ovkm Ownership Verification Key Material
   * @returns 登録に成功すると true
   */
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
    // 面倒なので アテステーションキー自体の検証は考慮していない
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
      // ユーザデータベースにないので、新規登録を開始する
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
    if (cm.isUpdating()) {
      // アカウントの OVK が更新中 なので、クレデンシャルの新規登録は受け付けられない
      return false;
    }
    // OVK を利用してクレデンシャルの検証を行う。
    const ovk = await ECPubKey.fromJWK(cm.getOVK());
    if (!(await ovk.verify(UTF8(JSON.stringify(cred.jwk)), BASE64URL_DECODE(ovkm.sig_b64u)))) {
      // OVK を使ってクレデンシャルの検証に失敗
      return false;
    }
    return cm.add(cred.jwk);
  }

  /**
   * ユーザを認証する。
   * @param name ユーザ名
   * @param cred_jwk 今回利用したクレデンシャル
   * @param sig_b64u チャレンジレスポンス
   * @param updating OVKの更新を行うなら、それら情報
   * @returns 認証に成功すれば true
   */
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
      // updating メッセージがあればそれを処理する
      if (!(await this.update(name, cred_jwk, updating.update_b64u, updating.ovkm))) {
        return false;
      }
    }
    const challenge_b64u = this.challengeDB[name].pop();
    if (!challenge_b64u) {
      return false;
    }
    const cm = this.db[name];
    // このユーザのクレデンシャルが存在しないか、また送られてきたクレデンシャルが登録済みでないなら
    if (!cm || !cm.isCred(cred_jwk)) {
      return false;
    }
    const cred = await ECPubKey.fromJWK(cred_jwk);
    return cred.verify(BASE64URL_DECODE(challenge_b64u), BASE64URL_DECODE(sig_b64u));
  }

  /**
   * updating を行う
   * @param name ユーザ名
   * @param update_b64u update メッセージ
   * @param ovkm_next 更新先の OVKM
   * @returns update の処理に成功すれば true
   */
  private async update(
    name: string,
    cred_jwk: ECPubJWK,
    update_b64u: string,
    ovkm_next: {
      ovk_jwk: ECPubJWK;
      r_b64u: string;
      mac_b64u: string;
    }
  ): Promise<boolean> {
    const cm = this.db[name];
    if (!cm) {
      // 未登録ユーザの update 処理はしない
      return false;
    }
    // 現在信頼している OVK を取得して
    const ovk = await ECPubKey.fromJWK(cm.getOVK());
    if (
      // 新しい OVK 候補が以前の OVK で署名しているか検証する
      !(await ovk.verify(UTF8(JSON.stringify(ovkm_next.ovk_jwk)), BASE64URL_DECODE(update_b64u)))
    ) {
      return false;
    }
    return cm.addUpdating(cred_jwk, ovkm_next.ovk_jwk, ovkm_next.r_b64u, ovkm_next.mac_b64u);
  }

  /**
   * ユーザを削除する。
   * @param name ユーザ名
   */
  async delete(name: string): Promise<void> {
    this.db[name] = undefined;
    return;
  }
}

/**
 * ユーザごとのクレデンシャル と OVK を管理する
 */
class CredManager {
  private constructor(
    // jwk がクレデンシャルの JWK 表現で、紐づく ovk と一緒に保存
    private creds: { jwk: ECPubJWK; ovk: ECPubJWK }[],
    // 現在信頼している OVK とメタデータ
    private ovkm: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string },
    // OVK の migate を行う途中に登録された OVK たち
    private next?: {
      candidates: { ovk_jwk: ECPubJWK; r_b64u: string; mac_b64u: string; firstTime: number }[];
      // updating が行われた時刻 (ms)
      startTime: number;
    }
  ) {}

  /**
   * アカウント新規登録時に、そのユーザに対して CredManeger を生成する。
   * @param cred_jwk 登録する１つめのクレデンシャル
   * @param ovkm 登録する OVK
   */
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

  /**
   * OVK で検証が行われたクレデンシャルを追加登録する
   * @param cred_jwk
   * @returns
   */
  add(cred_jwk: ECPubJWK): boolean {
    const ovk = this.getOVK();
    this.creds.push({ jwk: cred_jwk, ovk });
    return true;
  }

  /**
   * OVK の更新が行われている途中かどうか判定する。
   * 更新時刻を超えていれば、 OVK 更新処理をする。
   * @returns 更新中なら true
   */
  isUpdating(): boolean {
    // update メッセージがひとつも届いていないなら updating 中ではない
    if (!this.next) {
      return false;
    }
    // 更新中で、更新期間内であれば true
    const now = Date.now();
    if (now - this.next.startTime <= migrating_date_ms) {
      return true;
    }
    // 時刻が migration 開始時刻から指定の時間だけ過ぎていれば、
    // この時点で一番多くクレデンシャルと紐づく OVK を信頼する。
    // 同数の場合は、早く登録された方を信頼する。
    const ovks = this.creds.reduce(
      (ovks, c) => {
        for (let count = 0; count < ovks.length; count++) {
          for (let idx = 0; idx < ovks[count].length; idx++) {
            if (equalECPubJWK(c.ovk, ovks[count][idx])) {
              if (ovks[count + 1]) {
                ovks[count + 1].push(c.ovk);
              } else {
                ovks[count + 1] = [c.ovk];
              }
            }
          }
        }
        ovks[0].push(c.ovk);
        return ovks;
      },
      [[]] as Array<Array<ECPubJWK>>
    );
    let ovk: ECPubJWK;
    if (ovks[ovks.length - 1].length === 1) {
      // 一番多くクレデンシャルと紐づく ovk を採用
      ovk = ovks[ovks.length - 1][0];
    } else {
      // 一番多くクレデンシャルと紐づく ovk が複数ある時は、早く登録された方を選択する。
      let registered: number | undefined;
      for (const candidate of ovks[ovks.length - 1]) {
        // candidate はもともとの OVK かもしれないので、その時は next に含まれていない。
        // その場合は登録時刻が undefined になる。
        const r = this.next.candidates.find((c) => equalECPubJWK(candidate, c.ovk_jwk))?.firstTime;
        if (!registered || (r && r < registered)) {
          registered = r;
          ovk = candidate;
        }
      }
    }
    const ovkm = this.next.candidates.find((c) => equalECPubJWK(c.ovk_jwk, ovk)) ?? this.ovkm;
    this.ovkm = ovkm;
    this.next = undefined;
    this.creds = this.creds.filter((c) => equalECPubJWK(c.ovk, ovk));
    console.log(this.ovkm, this.next, this.creds);
    return false;
  }

  addUpdating(cred_jwk: ECPubJWK, ovk_jwk: ECPubJWK, r_b64u: string, mac_b64u: string): boolean {
    // cred_jwk に対応する ovk を更新するため、インデックスを取得する
    const idx = this.creds.findIndex((c) => equalECPubJWK(c.jwk, cred_jwk));
    if (idx === -1) {
      // cred_jwk が登録済みでない場合は無視
      return false;
    }
    // cred_jwk に対応する ovk を更新
    this.creds[idx].ovk = ovk_jwk;

    // ovk_jwk を next に追加する
    const now = Date.now();
    if (!this.next) {
      this.next = { candidates: [], startTime: now };
    }
    // next に 更新先の候補である ovk_jwk が登録済みかチェック
    if (!this.next.candidates.some((next) => equalECPubJWK(next.ovk_jwk, ovk_jwk))) {
      this.next.candidates.push({ ovk_jwk, r_b64u, mac_b64u, firstTime: now });
    }

    // 登録済みのクレデンシャルの数
    const cred_num = this.creds.length;
    // 更新先の候補である ovk_jwk に紐づくクレデンシャルの数
    const next_ovk_num = this.creds.filter((c) => equalECPubJWK(c.ovk, ovk_jwk)).length;
    if (cred_num / 2 < next_ovk_num) {
      // 登録済みクレデンシャルの過半数が賛同したので、その OVK を信用する。
      this.ovkm = { ovk_jwk, r_b64u, mac_b64u };
      this.next = undefined;
      this.creds = this.creds.filter((c) => equalECPubJWK(c.ovk, ovk_jwk));
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
    if (this.isUpdating()) {
      return {
        creds: this.creds.map((c) => c.jwk),
        ovkm: {
          ovk_jwk: this.ovkm.ovk_jwk,
          r_b64u: this.ovkm.r_b64u,
          mac_b64u: this.ovkm.mac_b64u,
          next: this.next?.candidates,
        },
      };
    }
    return {
      creds: this.creds.map((c) => c.jwk),
      ovkm: {
        ovk_jwk: this.ovkm.ovk_jwk,
        r_b64u: this.ovkm.r_b64u,
        mac_b64u: this.ovkm.mac_b64u,
      },
    };
  }

  /**
   * クレデンシャルが登録済みか判定する
   * @param cred_jwk 登録済みと思われるクレデンシャル
   * @returns 登録済みなら true
   */
  isCred(cred_jwk: ECPubJWK): boolean {
    return this.creds.some((c) => equalECPubJWK(c.jwk, cred_jwk));
  }

  /**
   *
   * @returns
   */
  getOVK(): ECPubJWK {
    return this.ovkm.ovk_jwk;
  }
}
