'use strict';

var fs = require('fs');
var http = require('http');

/**
 * node では webcryoto がライブラリで提供されているのでそれを使う。
 * BASE64 関連は Buffer で実装する。
 */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { subtle, getRandomValues } = require('crypto').webcrypto;
/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
function BASE64URL$1(OCTETS) {
    return Buffer.from(OCTETS).toString('base64url');
}
/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 */
function BASE64URL_DECODE$1(STRING) {
    return Buffer.from(STRING, 'base64url');
}
const RuntimeUtility = {
    BASE64URL: BASE64URL$1,
    BASE64URL_DECODE: BASE64URL_DECODE$1,
    subtle,
    getRandomValues,
};

/**
 * 文字列を UTF8 バイト列に変換する
 * @param STRING 変換対象の文字列
 * @returns STRING の UTF8 バイト列
 */
function UTF8(STRING) {
    const encoder = new TextEncoder();
    return encoder.encode(STRING);
}
/**
 * 16進数の文字列を Uint8Array に変換する。
 * len を与えない時は hexstr の長さにする。
 * @param hexstr 16進数の文字列
 * @param len 求めるバイナリ列の長さ。 hexstr の方が大きい時は TypeError を投げる。
 * hexstr の方が短い時は先頭を 0 padding する。
 * @returns hexstr を Uint8Array で表現したもの
 */
function HexStr2Uint8Array(hexstr, len) {
    // len があれば、hexstr で足りない分を先頭 0 padding する。
    // len がないなら、 hexstr が奇数長の場合に先頭 0 padding する
    let ans_str;
    if (len) {
        if (hexstr.length <= len * 2) {
            ans_str = '0'.repeat(len * 2 - hexstr.length) + hexstr;
        }
        else {
            throw new TypeError(`hexstr が len よりも長い`);
        }
    }
    else {
        if (hexstr.length % 2 === 1) {
            ans_str = '0' + hexstr;
        }
        else {
            ans_str = hexstr;
        }
    }
    const ans_length = ans_str.length / 2;
    const ans = new Uint8Array(ans_length);
    for (let i = 0; i < ans_length; i++) {
        ans[i] = parseInt(ans_str.substr(i * 2, 2), 16);
    }
    return ans;
}
/**
 * Uint8Array を16進数文字列に変換する。
 * @param arr バイナリ列
 * @param len 16進数文字列にした時のバイナリ長(結果は len の2倍の文字列になる)。
 * arr の方が長い時は TypeError をながる。 arr の方が短い時は先頭を 00-padding する。
 * @returns arr を16進数表現した文字列
 */
function Uint8Array2HexStr(arr, len) {
    const str_arr = Array.from(arr).map(function (e) {
        let hexchar = e.toString(16);
        if (hexchar.length == 1) {
            hexchar = '0' + hexchar;
        }
        return hexchar;
    });
    const ans = str_arr.join('');
    if (len) {
        if (ans.length <= len * 2) {
            return '0'.repeat(len * 2 - ans.length) + ans;
        }
        else {
            throw new TypeError(`arr が len よりも長い`);
        }
    }
    else {
        return ans;
    }
}
/**
 * ２つのバイト列を結合する
 */
function CONCAT(A, B) {
    const ans = new Uint8Array(A.length + B.length);
    ans.set(A);
    ans.set(B, A.length);
    return ans;
}
/**
 * value を WouldBE<T> かどうか判定する。
 * T のプロパティを持つかもしれないところまで。
 */
const isObject = (value) => typeof value === 'object' && value !== null;
/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 * browser なら window.btoa で実装し、 node なら Buffer で実装する。
 */
const BASE64URL = RuntimeUtility.BASE64URL;
/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 * browser なら window.atob で実装し、 node なら Buffer で実装する。
 */
const BASE64URL_DECODE = RuntimeUtility.BASE64URL_DECODE;

/**
 * 乱数列を生成する。
 * @param len 生成したいランダム列の長さ(バイト列)
 * @returns 乱数列
 */
function RandUint8Array(len) {
    return RuntimeUtility.getRandomValues(new Uint8Array(len));
}

const isInfinitePoint = (arg) => arg === 'O';
/**
 * SEC1#2.2.1 Elliptic Curves over F_p を実装する。
 * E(F_p): y^2 = x^3 + ax + b (mod p)なので、パラメータは a,b,p
 * 実装に当たっては bigint を利用しているが、bigint は暗号処理に向かないため、本番運用は避けるべきである。
 * c.f.) https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography
 */
class PCurve {
    constructor(a, b, p) {
        this.a = a;
        this.b = b;
        this.p = p;
    }
    /**
     * k * p を行う
     * @param p 楕円曲線上の点
     * @param k 整数 in [1,p-1]
     * @returns p を k 回足した結果 k*p
     */
    exp(p, k) {
        const absk = k < 0n ? -k : k;
        const k_bin = absk.toString(2);
        let ans = 'O';
        for (let i = 0; i < k_bin.length; i++) {
            ans = this.double(ans);
            if (k_bin[i] === '1') {
                ans = this.add(ans, p);
            }
        }
        if (!isInfinitePoint(ans) && k < 0) {
            return { x: ans.x, y: -ans.y };
        }
        return ans;
    }
    /**
     * 点 P が楕円曲線のものか判定する。
     * @param P 楕円曲線の点と思われるもの
     * @returns 楕円曲線の点なら true
     */
    isPoint(P) {
        if (isInfinitePoint(P)) {
            return true;
        }
        const { x, y } = P;
        if (x < 0n || this.p <= x || y < 0n || this.p <= y) {
            return false;
        }
        // y^2
        const left = this.dbl(y);
        // x^3 + ax + b
        const right = this.mod(this.mul(this.dbl(x), x) + this.mul(this.a, x) + this.b);
        return left === right;
    }
    mod(a) {
        return mod(a, this.p);
    }
    mul(a, b) {
        return mul(a, b, this.p);
    }
    dbl(a) {
        return dbl(a, this.p);
    }
    inv(a) {
        return inv(a, this.p);
    }
    /**
     * 楕円曲線上の２点の加算を定義する
     */
    add(p1, p2) {
        // 無限遠点同志の足し算は、無限遠点
        if (isInfinitePoint(p1) && isInfinitePoint(p2)) {
            // O + O = O
            return 'O';
        }
        // 無限遠点と有限点の足し算は、有限点
        if (isInfinitePoint(p1)) {
            return p2;
        }
        if (isInfinitePoint(p2)) {
            return p1;
        }
        // x座標が同じで y座標が異なるか0の時は、無限遠点
        // すなわち (x,y) の逆元 - (x,y) === (x, -y)
        if (this.mod(p1.y + p2.y) === 0n) {
            return 'O';
        }
        // x座標が異なる場合は
        if (p1.x !== p2.x) {
            return this.addDiffFinitePoints(p1, p2);
        }
        // x座標が同じ場合(すなわち2倍)
        return this.doubleFinitePoint(p1);
    }
    /**
     * 2倍算を定義する。
     * @param p 楕円曲線の点
     * @returns p + p
     */
    double(p) {
        if (isInfinitePoint(p)) {
            return 'O';
        }
        return this.doubleFinitePoint(p);
    }
    // 異なる有限点の足し算を計算する。
    addDiffFinitePoints(p1, p2) {
        if (p1.x === p2.x) {
            throw new EvalError(`addDiffPoints function は異なる２点の加算しか行えません`);
        }
        const lambda = this.mul(p2.y - p1.y, this.inv(p2.x - p1.x));
        const x3 = this.mod(this.dbl(lambda) - p1.x - p2.x);
        const y3 = this.mod(this.mul(lambda, p1.x - x3) - p1.y);
        return { x: x3, y: y3 };
    }
    // 有限点の2倍を計算する。
    doubleFinitePoint(p) {
        const lambda = this.mul(3n * this.dbl(p.x) + this.a, this.inv(2n * p.y));
        const x3 = this.mod(this.dbl(lambda) - 2n * p.x);
        const y3 = this.mod(this.mul(lambda, p.x - x3) - p.y);
        return { x: x3, y: y3 };
    }
}
/**
 * a (mod n)
 */
const mod = (a, n) => {
    const ans = a % n;
    return ans < 0 ? ans + n : ans;
};
/**
 * a * b (mod n)
 */
const mul = (a, b, n) => mod(a * b, n);
/**
 * a^2 (mod n)
 */
const dbl = (a, n) => mod(a * a, n);
/**
 * a^(-1) (mod n) で逆元がなければエラー
 */
function inv(a, n) {
    // 拡張ユークリッドの誤除法
    // inputs: a,b: 正整数 (BigInt)
    // output: ax + by = d (d は a と b の最大公約数)
    //         {d: BigInt, a: BigInt, b: BigInt}
    function ex_euclid(a, b) {
        if (b === 0n) {
            // ax + 0*y = d の一つの解を計算する
            return { d: a, x: 1n, y: 0n };
        }
        // a = bq + r を代入した b(qx + r) + rx = d が分かれば
        const z = ex_euclid(b, a % b);
        // ax + by = d は計算できる
        return { d: z.d, x: z.y, y: z.x - (a / b) * z.y };
    }
    while (a < 0)
        a += n;
    const z = ex_euclid(a, n);
    if (z.d != 1n) {
        throw new Error(`法 ${n} のもとで ${a} の逆元はない`);
    }
    return z.x % n;
}
/**
 * 楕円曲線の鍵ペアを実装する。
 */
class KeyPair {
    constructor(T, d, Q) {
        this.T = T;
        this.d = d;
        this.Q = Q;
    }
    /**
     * SEC1#3.2.1 EC Key Pair Generation Primitive
     * @param T 楕円曲線のドメインパラメータ
     * @param d 秘密鍵
     * @returns 鍵ペア
     */
    static gen(T, d) {
        if (!d) {
            const d_u8a = RandUint8Array(T.n.toString(16).length / 2);
            d = BigInt('0x' + Uint8Array2HexStr(d_u8a));
        }
        else if (d < 0n || T.n <= d) {
            throw new TypeError(`秘密鍵のサイズが不適切`);
        }
        const Q = T.crv.exp(T.G, d);
        if (isInfinitePoint(Q)) {
            throw new EvalError(`d が不適切`);
        }
        return new KeyPair(T, d, Q);
    }
    computeDH(Q) {
        const c = this.T.crv.exp(Q, this.d);
        if (isInfinitePoint(c)) {
            throw new EvalError(`DHの計算結果が無限遠点です`);
        }
        return c;
    }
    isValidate() {
        if (isInfinitePoint(this.Q)) {
            return false;
        }
        if (!this.T.crv.isPoint(this.Q)) {
            return false;
        }
        if (this.T.h !== 1n && !isInfinitePoint(this.T.crv.exp(this.Q, this.T.n))) {
            return false;
        }
        return true;
    }
    toJWK(isPublic = false) {
        const x = BASE64URL(HexStr2Uint8Array(this.Q.x.toString(16), this.T.n.toString(16).length / 2));
        const y = BASE64URL(HexStr2Uint8Array(this.Q.y.toString(16), this.T.n.toString(16).length / 2));
        if (isPublic) {
            return { kty: 'EC', crv: this.T.name.jwk, x, y };
        }
        const d = BASE64URL(HexStr2Uint8Array(this.d.toString(16), this.T.n.toString(16).length / 2));
        return { kty: 'EC', crv: this.T.name.jwk, x, y, d };
    }
}
/**
 * secp256r1 のドメインパラメータ
 */
const secp256r1 = {
    name: { jwk: 'P-256' },
    crv: new PCurve(BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'), BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'), BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff')),
    G: {
        x: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
        y: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
    },
    n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
    h: 1n,
};

/**
 * SHA-256 ハッシュ関数を実装する。
 * @param m メッセージ
 * @returns メッセージの SHA-256 ハッシュ値
 */
const SHA256 = async (m) => {
    const dgst = await RuntimeUtility.subtle.digest('SHA-256', m);
    return new Uint8Array(dgst);
};
/**
 * ECDSA over P-256 を実装する。
 * gen で EC 秘密鍵を生成もしくは、秘密鍵から公開鍵を導出する。
 * sign で署名を行い、 verify で署名を検証する。
 * dh で DH 計算を行う。
 */
const ECP256 = {
    /**
     * 秘密鍵を生成する。
     * @param secret 秘密鍵成分
     * @returns 秘密鍵成分から導出した公開鍵を含む秘密鍵
     */
    async gen(secret) {
        const d = secret ? BigInt('0x' + Uint8Array2HexStr(secret, secret.length)) : undefined;
        return KeyPair.gen(secp256r1, d).toJWK();
    },
    /**
     * 秘密鍵でメッセージの署名値を作成する。
     * @param sk EC秘密鍵
     * @param m メッセージ
     * @returns 署名値
     */
    async sign(sk, m) {
        const k_api = await RuntimeUtility.subtle.importKey('jwk', sk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
        const sig = await RuntimeUtility.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k_api, m);
        return new Uint8Array(sig);
    },
    /**
     * 公開鍵で署名を検証する。
     * @param pk EC公開鍵
     * @param m メッセージ
     * @param s 署名値
     * @returns 署名が正しければ true
     */
    async verify(pk, m, s) {
        const k = await RuntimeUtility.subtle.importKey('jwk', pk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        return await RuntimeUtility.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, s, m);
    },
    /**
     * DH計算を行う。
     * @param pk EC 公開鍵成分
     * @param sk EC 秘密鍵成分
     * @returns sk * pk した結果
     */
    async dh(pk, sk) {
        const privKey = KeyPair.gen(secp256r1, BigInt('0x' + Uint8Array2HexStr(BASE64URL_DECODE(sk.d), 32)));
        const pubKey = {
            x: BigInt('0x' + Uint8Array2HexStr(BASE64URL_DECODE(pk.x), 32)),
            y: BigInt('0x' + Uint8Array2HexStr(BASE64URL_DECODE(pk.y), 32)),
        };
        const bp = privKey.computeDH(pubKey);
        return {
            kty: 'EC',
            crv: 'P-256',
            x: BASE64URL(HexStr2Uint8Array(bp.x.toString(16), 32)),
            y: BASE64URL(HexStr2Uint8Array(bp.y.toString(16), 32)),
        };
    },
};

const isECPubJWK = (arg) => isObject(arg) &&
    arg.kty === 'EC' &&
    (!arg.kid || typeof arg.kid === 'string') &&
    typeof arg.crv === 'string' &&
    typeof arg.x === 'string' &&
    typeof arg.y === 'string';
/**
 * ２つの ECPubJWK が等しいかどうか判定する
 * @param l ECPubJWK で undefined でも良い;
 * @param r ECPubJWK で undefined でも良い;
 * @returns 二つの ECPubJWK のプロパティが全て等しければ true
 */
function equalECPubJWK(l, r) {
    if (!l && !r)
        return true;
    if (!l || !r)
        return false;
    return l.kid === r.kid && l.crv === r.crv && l.x === r.x && l.y === r.y;
}
/**
 * EC 公開鍵を表現するクラス。
 * 署名の検証や kid の命名など行える。
 */
class ECPubKey {
    constructor(_x, _y, _kid) {
        this._x = _x;
        this._y = _y;
        this._kid = _kid;
    }
    x(format) {
        switch (format) {
            case 'b64u':
                return BASE64URL(this._x);
            case 'oct':
                return this._x;
        }
    }
    y(format) {
        switch (format) {
            case 'b64u':
                return BASE64URL(this._y);
            case 'oct':
                return this._y;
        }
    }
    /**
     * JWK 形式の EC 公開鍵から ECPubKey を生成する.
     * kid が JWK 似なければ JWK Thumbprint に従って kid も生成する。
     * @param jwk JWK 形式の公開鍵
     * @returns
     */
    static async fromJWK(jwk) {
        return new ECPubKey(BASE64URL_DECODE(jwk.x), BASE64URL_DECODE(jwk.y), jwk.kid ?? (await genKID(jwk)));
    }
    /**
     * この公開鍵を JWK で表現する。
     * @returns EC公開鍵の JWK 表現
     */
    toJWK() {
        return {
            kty: 'EC',
            kid: this._kid,
            crv: 'P-256',
            x: this.x('b64u'),
            y: this.y('b64u'),
        };
    }
    /**
     * この公開鍵を使って署名値の検証を行う
     * @param m 署名対象のメッセージ
     * @param s 署名値
     * @returns 署名の検証に成功すれば true
     */
    async verify(m, s) {
        return ECP256.verify(this.toJWK(), m, s);
    }
}
/**
 * RFC 7638 - JSON Web Key (JWK) Thumbprint に基づいて kid を生成する。
 * @param jwk KID 生成対象
 * @returns jwk.kid
 */
async function genKID(jwk) {
    const json = JSON.stringify({
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y,
    });
    const dgst = await SHA256(UTF8(json));
    return BASE64URL(dgst);
}

// マイグレーション時間は 3分 にしておく
const migrating_date_ms = 3 * 60 * 1000;
/**
 * 認証機能を持つサービスで、 OVK を利用したクレデンシャルの登録に対応している
 */
class Service {
    constructor(id) {
        this.id = id;
        this.db = {};
        this.challengeDB = {};
    }
    /**
     * サービスを作成する
     * @param id サービス識別子
     * @returns サービス
     */
    static gen(id) {
        return new Service(id);
    }
    /**
     * 認証リクエストを処理する。
     * @param name ユーザ名
     * @returns 登録済みなら登録済みクレデンシャルと ovk を返し、未登録ならチャレンジだけ返す
     */
    async startAuthn(name) {
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
    async register(name, cred, ovkm) {
        const challenge_b64u = this.challengeDB[name].pop();
        if (!challenge_b64u) {
            return false;
        }
        // cred のアテステーションを検証する.
        // 面倒なので アテステーションキー自体の検証は考慮していない
        const pk_atts = await ECPubKey.fromJWK(cred.atts.key);
        if (!(await pk_atts.verify(CONCAT(BASE64URL_DECODE(challenge_b64u), UTF8(JSON.stringify(cred.jwk))), BASE64URL_DECODE(cred.atts.sig_b64u)))) {
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
            }
            else {
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
    async authn(name, cred_jwk, sig_b64u, updating) {
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
    async update(name, cred_jwk, update_b64u, ovkm_next) {
        const cm = this.db[name];
        if (!cm) {
            // 未登録ユーザの update 処理はしない
            return false;
        }
        // 現在信頼している OVK を取得して
        const ovk = await ECPubKey.fromJWK(cm.getOVK());
        if (
        // 新しい OVK 候補が以前の OVK で署名しているか検証する
        !(await ovk.verify(UTF8(JSON.stringify(ovkm_next.ovk_jwk)), BASE64URL_DECODE(update_b64u)))) {
            return false;
        }
        return cm.addUpdating(cred_jwk, ovkm_next.ovk_jwk, ovkm_next.r_b64u, ovkm_next.mac_b64u);
    }
    /**
     * ユーザを削除する。
     * @param name ユーザ名
     */
    async delete(name) {
        this.db[name] = undefined;
        return;
    }
}
/**
 * ユーザごとのクレデンシャル と OVK を管理する
 */
class CredManager {
    constructor(
    // jwk がクレデンシャルの JWK 表現で、紐づく ovk と一緒に保存
    creds, 
    // 現在信頼している OVK とメタデータ
    ovkm, 
    // OVK の migate を行う途中に登録された OVK たち
    next) {
        this.creds = creds;
        this.ovkm = ovkm;
        this.next = next;
    }
    /**
     * アカウント新規登録時に、そのユーザに対して CredManeger を生成する。
     * @param cred_jwk 登録する１つめのクレデンシャル
     * @param ovkm 登録する OVK
     */
    static init(cred_jwk, ovkm) {
        return new CredManager([{ jwk: cred_jwk, ovk: ovkm.ovk_jwk }], ovkm);
    }
    /**
     * OVK で検証が行われたクレデンシャルを追加登録する
     * @param cred_jwk
     * @returns
     */
    add(cred_jwk) {
        const ovk = this.getOVK();
        this.creds.push({ jwk: cred_jwk, ovk });
        return true;
    }
    /**
     * OVK の更新が行われている途中かどうか判定する。
     * 更新時刻を超えていれば、 OVK 更新処理をする。
     * @returns 更新中なら true
     */
    isUpdating() {
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
        const ovks = this.creds.reduce((ovks, c) => {
            for (let count = 0; count < ovks.length; count++) {
                for (let idx = 0; idx < ovks[count].length; idx++) {
                    if (equalECPubJWK(c.ovk, ovks[count][idx])) {
                        if (ovks[count + 1]) {
                            ovks[count + 1].push(c.ovk);
                        }
                        else {
                            ovks[count + 1] = [c.ovk];
                        }
                    }
                }
            }
            ovks[0].push(c.ovk);
            return ovks;
        }, [[]]);
        let ovk;
        if (ovks[ovks.length - 1].length === 1) {
            // 一番多くクレデンシャルと紐づく ovk を採用
            ovk = ovks[ovks.length - 1][0];
        }
        else {
            // 一番多くクレデンシャルと紐づく ovk が複数ある時は、早く登録された方を選択する。
            let registered;
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
    addUpdating(cred_jwk, ovk_jwk, r_b64u, mac_b64u) {
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
    getCreds() {
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
    isCred(cred_jwk) {
        return this.creds.some((c) => equalECPubJWK(c.jwk, cred_jwk));
    }
    /**
     *
     * @returns
     */
    getOVK() {
        return this.ovkm.ovk_jwk;
    }
}

const isovkm = (arg) => isObject(arg) &&
    isECPubJWK(arg.ovk_jwk) &&
    typeof arg.r_b64u === 'string' &&
    typeof arg.mac_b64u === 'string';
const isStartAuthnRequestMessage = (arg) => isObject(arg) && typeof arg.username === 'string';
const isRegistrationRequestMessage = (arg) => isObject(arg) &&
    typeof arg.username === 'string' &&
    isObject(arg.cred) &&
    isECPubJWK(arg.cred.jwk) &&
    isObject(arg.cred.atts) &&
    typeof arg.cred.atts.sig_b64u === 'string' &&
    isECPubJWK(arg.cred.atts.key) &&
    (isovkm(arg.ovkm) ||
        (isObject(arg.ovkm) && typeof arg.ovkm.sig_b64u === 'string'));
const isAuthnRequestMessage = (arg) => isObject(arg) &&
    typeof arg.username === 'string' &&
    isECPubJWK(arg.cred_jwk) &&
    typeof arg.sig_b64u === 'string' &&
    (!arg.updating ||
        (isObject(arg.updating) &&
            typeof arg.updating?.update_b64u === 'string' &&
            isovkm(arg.updating.ovkm)));

const svcList = ['svc1', 'svc2', 'svc3'];
const Services = svcList.reduce((obj, svc) => {
    obj[svc] = Service.gen(svc);
    return obj;
}, {});
const server = http.createServer(async (req, resp) => {
    // クライアント一式（静的ファイル）を返す。
    if (['/', '/index.html', '/client.js', '/pico.min.css'].includes(req.url ?? '')) {
        const filePath = './publish' + (!req.url || req.url === '/' ? '/index.html' : req.url);
        let contentType;
        if (filePath.endsWith('.html')) {
            contentType = 'text/html';
        }
        else if (filePath.endsWith('.js')) {
            contentType = 'text/javascript';
        }
        else if (filePath.endsWith('.css')) {
            contentType = 'text/css';
        }
        else {
            contentType = 'application/octet-stram';
        }
        fs.readFile(filePath, (err, content) => {
            if (err) {
                resp.writeHead(500);
                resp.end('Sorry, check with the site admin for error: ' + err.code + ' ..\n');
                resp.end();
                console.log(`${req.url}: error with 500`);
            }
            else {
                resp.writeHead(200, { 'Content-Type': contentType });
                resp.end(content, 'utf-8');
                console.log(`${req.url}: return the static file`);
            }
        });
        return;
    }
    // サービスとしてユーザ登録 or ログインを処理する
    if (['/svc'].some((p) => req.url?.startsWith(p))) {
        let svc;
        if (req.url?.startsWith('/svc1')) {
            svc = 'svc1';
        }
        else if (req.url?.startsWith('/svc2')) {
            svc = 'svc2';
        }
        else if (req.url?.startsWith('/svc3')) {
            svc = 'svc3';
        }
        else {
            resp.writeHead(500, { 'Content-Type': 'application/json' });
            resp.end(JSON.stringify({ err: `no such svc request-url: ${req.url}` }));
            console.log(`error with 500`);
            console.groupEnd();
            return;
        }
        let action;
        if (req.url?.endsWith('/register')) {
            action = 'register';
        }
        else if (req.url?.endsWith('/login')) {
            action = 'login';
        }
        else if (req.url?.endsWith('/access')) {
            action = 'access';
        }
        else if (req.url?.endsWith('/reset')) {
            action = 'reset';
        }
        else {
            resp.writeHead(500, { 'Content-Type': 'application/json' });
            resp.end(JSON.stringify({ err: `no such action request-url: ${req.url}` }));
            console.log(`${req.url}: error with 500`);
            return;
        }
        const Svc = Services[svc];
        req.setEncoding('utf8');
        req.on('data', async (chunk) => {
            const data = JSON.parse(chunk);
            switch (action) {
                case 'access': {
                    if (!isStartAuthnRequestMessage(data)) {
                        resp.writeHead(401, { 'Content-Type': 'application/json' });
                        resp.end(JSON.stringify({ err: `formatting error: ${req.url}` }));
                        console.log(`${req.url}: error with 401`);
                        return;
                    }
                    const r = await Svc.startAuthn(data.username);
                    resp.writeHead(200, { 'Content-Type': 'application/json' });
                    resp.end(JSON.stringify(r));
                    console.log(`${req.url}:\n  req: ${JSON.stringify(data)}\n  resp: ${JSON.stringify(r)}`);
                    return;
                }
                case 'register': {
                    if (!isRegistrationRequestMessage(data)) {
                        resp.writeHead(401, { 'Content-Type': 'application/json' });
                        resp.end(JSON.stringify({ err: `formatting error: ${req.url}` }));
                        console.log(`${req.url}:: error with 401`);
                        return;
                    }
                    const r = await Svc.register(data.username, data.cred, data.ovkm);
                    resp.writeHead(200, { 'Content-Type': 'application/json' });
                    resp.end(JSON.stringify(r));
                    console.log(`${req.url}:\n  req: ${JSON.stringify(data)}\n  resp: ${JSON.stringify(r)}`);
                    return;
                }
                case 'login': {
                    if (!isAuthnRequestMessage(data)) {
                        resp.writeHead(401, { 'Content-Type': 'application/json' });
                        resp.end(JSON.stringify({ err: `formatting error: ${req.url}` }));
                        console.log(`${req.url}: error with 401`);
                        return;
                    }
                    const r = await Svc.authn(data.username, data.cred_jwk, data.sig_b64u, data.updating);
                    resp.writeHead(200, { 'Content-Type': 'application/json' });
                    resp.end(JSON.stringify(r));
                    console.log(`${req.url}:\n  req: ${JSON.stringify(data)}\n  resp: ${JSON.stringify(r)}`);
                    return;
                }
                case 'reset': {
                    // デバック用にサービスの認証情報をリセットする
                    if (!isStartAuthnRequestMessage(data)) {
                        resp.writeHead(401, { 'Content-Type': 'application/json' });
                        resp.end(JSON.stringify({ err: `formatting error: ${req.url}` }));
                        console.log(`${req.url}: error with 401`);
                        return;
                    }
                    await Svc.delete(data.username);
                    resp.writeHead(200, { 'Content-Type': 'application/json' });
                    resp.end();
                    console.log(`${req.url}:\n  user: ${data.username}`);
                }
            }
        });
        return;
    }
    resp.writeHead(404);
    resp.end();
    console.log(`${req.url}: error with 404`);
});
server.listen(8080);
