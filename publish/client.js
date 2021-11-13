'use strict';

/**
 * バイト列を BASE64URL エンコードする (Uint8Array to string)
 */
function BASE64URL$1(OCTETS) {
    // window 組み込みの base64 encode 関数
    // 組み込みの関数は引数としてバイナリ文字列を要求するため
    // Uint8Array をバイナリ文字列へと変換する
    const b_str = String.fromCharCode(...OCTETS);
    const base64_encode = window.btoa(b_str);
    return (base64_encode
        // 文字「+」は全て「-」へ変換する
        .replaceAll('+', '-')
        // 文字「/」は全て「_」へ変換する
        .replaceAll('/', '_')
        // 4の倍数にするためのパディング文字は全て消去
        .replaceAll('=', ''));
}
/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
 */
function BASE64URL_DECODE$1(STRING) {
    const url_decode = STRING
        // URL-safe にするために変換した文字たちを戻す
        .replaceAll('-', '+')
        .replaceAll('_', '/')
        // 文字列長が4の倍数になるように padding文字で埋める
        .padEnd(Math.ceil(STRING.length / 4) * 4, '=');
    // window 組み込みの base64 decode 関数
    // この関数はデコードの結果をバイナリ文字列として出力する
    const b_str = window.atob(url_decode);
    // バイナリ文字列を Uint8Array に変換する
    const b = new Uint8Array(b_str.length);
    for (let i = 0; i < b_str.length; i++) {
        b[i] = b_str.charCodeAt(i);
    }
    return b;
}
const RuntimeUtility = {
    BASE64URL: BASE64URL$1,
    BASE64URL_DECODE: BASE64URL_DECODE$1,
    subtle: window.crypto.subtle,
    getRandomValues(x) {
        return window.crypto.getRandomValues(x);
    },
};

/**
 * 文字列を UTF8 バイトエンコードする。(string to Uint8Array)
 */
function UTF8(STRING) {
    const encoder = new TextEncoder();
    return encoder.encode(STRING);
}
/**
 * 文字列に UTF8 バイトデコードする (Uint8Array to string)
 */
function UTF8_DECODE(OCTETS) {
    const decoder = new TextDecoder();
    return decoder.decode(OCTETS);
}
/**
 * 文字列を ASCII バイトエンコードする。 (string to Uint8Array)
 */
function ASCII(STRING) {
    const b = new Uint8Array(STRING.length);
    for (let i = 0; i < STRING.length; i++) {
        b[i] = STRING.charCodeAt(i);
    }
    return b;
}
function HexStr2Uint8Array(hexstr, len) {
    let ans_str = hexstr;
    if (hexstr.length < len * 2) {
        ans_str = '0'.repeat(len * 2 - hexstr.length) + hexstr;
    }
    const ans_length = ans_str.length / 2;
    const ans = new Uint8Array(ans_length);
    for (let i = 0; i < ans_length; i++) {
        ans[i] = parseInt(ans_str.substr(i * 2, 2), 16);
    }
    return ans;
}
function Uint8Array2HexStr(arr, len) {
    const str_arr = Array.from(arr).map(function (e) {
        let hexchar = e.toString(16);
        if (hexchar.length == 1) {
            hexchar = '0' + hexchar;
        }
        return hexchar;
    });
    let ans = str_arr.join('');
    if (ans.length < len * 2) {
        ans = '0'.repeat(len * 2 - ans.length) + ans;
    }
    return ans;
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
 */
const BASE64URL = RuntimeUtility.BASE64URL;
/**
 * バイト列に BASE64URL デコードする (string to Uint8Array)
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
 * SEC1#2.2.1 Elliptic Curves over F_p
 * bigint は暗号処理に向かないため、本番運用は避けるべきである。
 * c.f.) https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography
 */
class PCurve {
    constructor(a, b, p) {
        this.a = a;
        this.b = b;
        this.p = p;
    }
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
    isPoint(P) {
        if (isInfinitePoint(P)) {
            return true;
        }
        const { x, y } = P;
        if (x < 0n || this.p <= x || y < 0n || this.p <= y) {
            return false;
        }
        const left = mod(y * y, this.p);
        const right = mod(mul(dbl(x, this.p), x, this.p) + mul(this.a, x, this.p) + this.b, this.p);
        return left === right;
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
        if (mod(p1.y + p2.y, this.p) === 0n) {
            return 'O';
        }
        // x座標が異なる場合は
        if (p1.x !== p2.x) {
            return this.addDiffFinitePoints(p1, p2);
        }
        // x座標が同じ場合(すなわち2倍)
        return this.doubleFinitePoint(p1);
    }
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
        const lambda = mul(p2.y - p1.y, inv(p2.x - p1.x, this.p), this.p);
        const x3 = mod(dbl(lambda, this.p) - p1.x - p2.x, this.p);
        const y3 = mod(mul(lambda, p1.x - x3, this.p) - p1.y, this.p);
        return { x: x3, y: y3 };
    }
    // 有限点の2倍を計算する。
    doubleFinitePoint(p) {
        const lambda = mul(3n * dbl(p.x, this.p) + this.a, inv(2n * p.y, this.p), this.p);
        const x3 = mod(dbl(lambda, this.p) - 2n * p.x, this.p);
        const y3 = mod(mul(lambda, p.x - x3, this.p) - p.y, this.p);
        return { x: x3, y: y3 };
    }
}
const mod = (a, n) => {
    const ans = a % n;
    return ans < 0 ? ans + n : ans;
};
const mul = (a, b, n) => mod(a * b, n);
const dbl = (a, n) => mod(a * a, n);
// 法 n のもと、元 a の逆元を返す関数。逆元がなければエラー。
// inputs: a,n: 整数 (BigInt)
// output: a^(-1) mod n があればそれを返す。
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
            const len = T.n.toString(16).length;
            const d_u8a = RandUint8Array(len / 2);
            d = BigInt('0x' + Uint8Array2HexStr(d_u8a, len / 2));
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
        const x = BASE64URL(HexStr2Uint8Array(this.Q.x.toString(16), 32));
        const y = BASE64URL(HexStr2Uint8Array(this.Q.y.toString(16), 32));
        if (isPublic) {
            return { kty: 'EC', crv: this.T.name.jwk, x, y };
        }
        const d = BASE64URL(HexStr2Uint8Array(this.d.toString(16), 32));
        return { kty: 'EC', crv: this.T.name.jwk, x, y, d };
    }
}
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

const HKDF = async (key, salt, length) => {
    const k = await RuntimeUtility.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits']);
    const derivedKeyMaterial = await RuntimeUtility.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array() }, k, length);
    return new Uint8Array(derivedKeyMaterial);
};
const SHA256 = async (m) => {
    const dgst = await RuntimeUtility.subtle.digest('SHA-256', m);
    return new Uint8Array(dgst);
};
const HMAC = {
    async mac(key, m) {
        const sk_api = await RuntimeUtility.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const mac = await RuntimeUtility.subtle.sign('HMAC', sk_api, m);
        return new Uint8Array(mac);
    },
    async verify(key, m, mac) {
        const sk_api = await RuntimeUtility.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        return await RuntimeUtility.subtle.verify('HMAC', sk_api, mac, m);
    },
};
const ECP256 = {
    async gen(secret) {
        const d = secret ? BigInt('0x' + Uint8Array2HexStr(secret, secret.length)) : undefined;
        return KeyPair.gen(secp256r1, d).toJWK();
    },
    async sign(sk, m) {
        const k_api = await RuntimeUtility.subtle.importKey('jwk', sk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
        const sig = await RuntimeUtility.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k_api, m);
        return new Uint8Array(sig);
    },
    async verify(pk, m, s) {
        const k = await RuntimeUtility.subtle.importKey('jwk', pk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        return await RuntimeUtility.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, k, s, m);
    },
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
const PBES2JWE = {
    async compact(pw, m) {
        // PBES2 用の JOSE Header を用意して
        const header = {
            alg: 'PBES2-HS256+A128KW',
            enc: 'A128GCM',
            p2c: 1000,
            p2s: BASE64URL(RandUint8Array(16)),
        };
        const header_b64u = BASE64URL(UTF8(JSON.stringify(header)));
        // Content Encryption Key を乱数生成する
        const cek = RandUint8Array(16);
        const cek_api = await RuntimeUtility.subtle.importKey('raw', cek, 'AES-GCM', true, ['encrypt']);
        // CEK を使って m を暗号化
        const iv = RandUint8Array(12);
        const e = new Uint8Array(await RuntimeUtility.subtle.encrypt({
            name: 'AES-GCM',
            iv,
            additionalData: ASCII(header_b64u),
        }, cek_api, m));
        const ciphertext = e.slice(0, e.length - 16);
        const atag = e.slice(e.length - 16);
        // PBES2 で導出した鍵で CEK をラップして Encrypted Key を生成する
        const dk_api = await RuntimeUtility.subtle.importKey('raw', await RuntimeUtility.subtle.deriveBits({
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
            iterations: header.p2c,
        }, await RuntimeUtility.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']), 128), { name: 'AES-KW' }, false, ['wrapKey']);
        const ek = new Uint8Array(await RuntimeUtility.subtle.wrapKey('raw', cek_api, dk_api, { name: 'AES-KW' }));
        const ek_b64u = BASE64URL(ek);
        return `${header_b64u}.${ek_b64u}.${BASE64URL(iv)}.${BASE64URL(ciphertext)}.${BASE64URL(atag)}`;
    },
    async dec(pw, compact) {
        const l = compact.split('.');
        if (l.length !== 5) {
            throw new EvalError('JWE Compact Serialization の形式ではない');
        }
        const [h_b64u, ek_b64u, iv_b64u, c_b64u, atag_b64u] = l;
        const header = JSON.parse(UTF8_DECODE(BASE64URL_DECODE(h_b64u)));
        // PBES2 で導出した鍵で EK をアンラップして CEK を得る
        const dk_api = await RuntimeUtility.subtle.importKey('raw', await RuntimeUtility.subtle.deriveBits({
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt: CONCAT(CONCAT(UTF8(header.alg), new Uint8Array([0])), BASE64URL_DECODE(header.p2s)),
            iterations: header.p2c,
        }, await RuntimeUtility.subtle.importKey('raw', UTF8(pw), 'PBKDF2', false, ['deriveBits']), 128), { name: 'AES-KW' }, false, ['unwrapKey']);
        const cek_api = await RuntimeUtility.subtle.unwrapKey('raw', BASE64URL_DECODE(ek_b64u), dk_api, {
            name: 'AES-KW',
        }, 'AES-GCM', true, ['decrypt']);
        // CEK を使って ciphertext と authentication tag から平文を復号し整合性を検証する
        const e = await RuntimeUtility.subtle.decrypt({ name: 'AES-GCM', iv: BASE64URL_DECODE(iv_b64u), additionalData: ASCII(h_b64u) }, cek_api, CONCAT(BASE64URL_DECODE(c_b64u), BASE64URL_DECODE(atag_b64u)));
        return new Uint8Array(e);
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
    static async fromJWK(jwk) {
        return new ECPubKey(BASE64URL_DECODE(jwk.x), BASE64URL_DECODE(jwk.y), jwk.kid ?? (await genKID(jwk)));
    }
    static is(arg) {
        return arg instanceof ECPubKey;
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
 * EC 秘密鍵を表現する。
 */
class ECPrivKey extends ECPubKey {
    constructor(_x, _y, _d, kid) {
        super(_x, _y, kid);
        this._d = _d;
    }
    d(format) {
        switch (format) {
            case 'b64u':
                return BASE64URL(this._d);
            case 'oct':
                return this._d;
        }
    }
    /**
     * 秘密鍵成分から EC 公開鍵を導出して ECPrivKey を作成するコンストラクタ
     * @param d 秘密鍵の d
     * @returns Promise<ECPrivKey>
     */
    static async fromSecret(d) {
        return ECPrivKey.fromJWK((await ECP256.gen(d)));
    }
    /**
     * JWK からECPrivKey を作成するコンストラクタ
     * @param jwk EC 秘密鍵の JWK 成分
     * @returns Promise<ECPrivKey>
     */
    static async fromJWK(jwk) {
        return new ECPrivKey(BASE64URL_DECODE(jwk.x), BASE64URL_DECODE(jwk.y), BASE64URL_DECODE(jwk.d), jwk.kid ?? (await genKID(jwk)));
    }
    /**
     * ランダムに ECPrivKey を作成するコンストラクタ
     * @returns Promise<ECPrivKey>
     */
    static async gen() {
        return ECPrivKey.fromJWK((await ECP256.gen()));
    }
    toECPubKey() {
        return this;
    }
    toJWK() {
        return {
            ...super.toJWK(),
            d: this.d('b64u'),
        };
    }
    /**
     * ECDH を行う
     * @param pk EC 公開鍵
     * @returns (this.d) * pk した結果の EC 公開鍵
     */
    async computeDH(pk) {
        return (await ECP256.dh(pk, this.toJWK()));
    }
    /**
     * この秘密鍵を使ってメッセージに対して署名する。
     * @param m 署名対象のメッセージ
     * @returns 署名値
     */
    async sign(m) {
        return ECP256.sign(this.toJWK(), m);
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

class Device {
    constructor(name, seed, attsKey, creds = [], negotiating) {
        this.name = name;
        this.seed = seed;
        this.attsKey = attsKey;
        this.creds = creds;
        this.negotiating = negotiating;
    }
    static async gen(name, seed) {
        return new Device(name, seed, await ECPrivKey.gen());
    }
    async initSeedNegotiation(pw, devID, partnerID, devNum, updating = false) {
        this.negotiating = { pw, devID, devNum, partnerID, epk: { mine: {}, partner: {} } };
        const { epk } = await this.seed.negotiate({ id: devID, partnerID, devNum }, undefined, updating);
        const m = UTF8(this.negotiating.devID + '.' + JSON.stringify(epk));
        return PBES2JWE.compact(this.negotiating.pw, m);
    }
    async seedNegotiating(ciphertext, updating = false) {
        if (!this.negotiating) {
            throw new EvalError(`シードのネゴシエーション初期化を行っていない`);
        }
        let m_received;
        try {
            m_received = await PBES2JWE.dec(this.negotiating.pw, ciphertext);
        }
        catch {
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
        const { completion, epk: epk_computed } = await this.seed.negotiate({
            id: this.negotiating.devID,
            partnerID: this.negotiating.partnerID,
            devNum: this.negotiating.devNum,
        }, this.negotiating.epk, updating);
        Object.assign(this.negotiating.epk.mine, epk_computed);
        const m_computed = UTF8(this.negotiating.devID + '.' + JSON.stringify(this.negotiating.epk.mine));
        const ciphertext_ans = await PBES2JWE.compact(this.negotiating.pw, m_computed);
        if (completion) {
            this.negotiating = undefined;
        }
        return { completion, ciphertext: ciphertext_ans };
    }
    async register(svc, ovkm) {
        // クレデンシャルの生成とアテステーション
        const cred_sk = await ECPrivKey.gen();
        const cred_pk_jwk = await (await cred_sk.toECPubKey()).toJWK();
        const sig_atts = await this.attsKey.sign(CONCAT(BASE64URL_DECODE(svc.challenge_b64u), UTF8(JSON.stringify(cred_pk_jwk))));
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
        }
        else {
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
    async authn(svc, ovkm) {
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
                const isVerified = await this.seed.verifyOVK(BASE64URL_DECODE(ovkm_i.r_b64u), svc.id, BASE64URL_DECODE(ovkm_i.mac_b64u));
                if (isVerified) {
                    return ovkm_i;
                }
            }
            return undefined;
        })(ovkm.next);
        if (ovkm_correct) {
            // すでに登録済みの nextOVK に対応する Update メッセージを送る
            const update = await this.seed.update(BASE64URL_DECODE(ovkm.r_b64u), await ECPubKey.fromJWK(ovkm_correct.ovk_jwk));
            return {
                cred_jwk,
                sig_b64u,
                updating: {
                    update_b64u: BASE64URL(update),
                    ovkm: ovkm_correct,
                },
            };
        }
        else {
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

function newSeed() {
    return new SeedImpl();
}
class SeedImpl {
    constructor(seeds = [], e) {
        this.seeds = seeds;
        this.e = e;
    }
    async negotiate(meta, epk, update = false) {
        // Updating かどうか、その場合のすでに所有済みのシードの一人の整合性をチェック
        if ((update && this.seeds.length === 0) || (!update && this.seeds.length !== 0)) {
            // updating 出ない時はシードを保有していないはずで、updating の時はシードを持っているはず
            throw new EvalError(`シードのネゴシエートを始める状態ではない`);
        }
        // ネゴシエート用の ephemeral data を用意する。ネゴシエートの途中ですでに生成済みならそれを使用し、なければ生成する。
        let e = this.e;
        if (e) {
            // すでにネゴシエータようのデータがあれば、 meta data が一致するかチェック
            if (e.meta.id !== meta.id ||
                e.meta.partnerID !== meta.partnerID ||
                e.meta.devNum !== meta.devNum) {
                // meta data はネゴシエートに参加するデバイスの一時的な識別子
                throw new EvalError(`シードのネゴシエート中に違うメタデータを使用している`);
            }
        }
        else {
            this.e = {
                sk: (await ECPrivKey.gen()).toJWK(),
                meta,
                idx: this.seeds.length,
            };
            e = this.e;
        }
        const sk = await ECPrivKey.fromJWK(e.sk);
        // このデバイスで生成する DH 公開鍵。 0 step は対応する公開鍵そのもの
        const ans = { 0: sk.toECPubKey().toJWK() };
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
                    }
                    else {
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
    get seed() {
        if (this.seeds.length == 0) {
            throw new EvalError(`Seed を保有していない`);
        }
        return this.seeds[this.seeds.length - 1];
    }
    async OVK(r, s) {
        const d = await HKDF(s ?? this.seed, r, 256);
        return ECPrivKey.fromSecret(d);
    }
    async deriveOVK(r) {
        const sk = await this.OVK(r);
        return sk.toECPubKey();
    }
    async macOVK(r, svcID) {
        const sk = await this.OVK(r);
        return await HMAC.mac(sk.d('oct'), CONCAT(r, UTF8(svcID)));
    }
    async verifyOVK(r, svcID, MAC) {
        const sk = await this.OVK(r);
        return await HMAC.verify(sk.d('oct'), CONCAT(r, UTF8(svcID)), MAC);
    }
    async signOVK(r, cred) {
        const sk = await this.OVK(r);
        return await sk.sign(cred);
    }
    async isUpdating() {
        return this.seeds.length > 1;
    }
    async update(prevR, nextOVK) {
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

const isovkm = (arg) => isObject(arg) &&
    isECPubJWK(arg.ovk_jwk) &&
    typeof arg.r_b64u === 'string' &&
    typeof arg.mac_b64u === 'string';
const isStartAuthnResponseMessage = (arg) => (isObject(arg) && typeof arg.challenge_b64u === 'string') ||
    (isObject(arg) &&
        typeof arg.challenge_b64u === 'string' &&
        Array.isArray(arg.creds) &&
        arg.creds.every(isECPubJWK) &&
        isObject(arg.ovkm) &&
        (!arg.ovkm.next || (Array.isArray(arg.ovkm.next) && arg.ovkm.next.every(isovkm))) &&
        isovkm(arg.ovkm));

const origin = 'http://localhost:8080';
let Dev;
const registeredUsers = {};
// Dev を初期化する
window.document.getElementById('dev-name')?.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!(e instanceof SubmitEvent) || !(e.submitter instanceof HTMLButtonElement)) {
        throw new TypeError(`不正な HTML Document ${e}`);
    }
    // DOM Validation
    if (!(this instanceof HTMLFormElement)) {
        throw new TypeError(`不正な HTML Document ${this}`);
    }
    const devnameE = this['dev-name'];
    if (!(devnameE instanceof HTMLInputElement)) {
        throw new TypeError(`不正な HTML Document ${devnameE}`);
    }
    // デバイスを初期化する
    Dev = await Device.gen(devnameE.value, newSeed());
    // 初期化を行なったのでこれ以上できないように disabled しておく
    devnameE.disabled = true;
    e.submitter.disabled = true;
    // シードの管理とサービスへのアクセスができるように表示する
    const devCtrl = window.document.getElementById('dev-controller');
    if (!devCtrl) {
        throw new TypeError(`不正な HTML Document ${document}`);
    }
    devCtrl.hidden = false;
    // シードの初期化画面に遷移
    window.location.href = '#seed-init-nego';
});
// シードの更新を行うかどうか判断する
const isUpdating = () => {
    const sw = window.document.getElementById('seed-updating');
    if (!(sw instanceof HTMLInputElement)) {
        throw new TypeError(`不正な HTML Document ${sw}`);
    }
    return sw.checked;
};
// シードネゴシエートの初期化を行う
window.document
    .getElementById('seed-init-nego-form')
    ?.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!(this instanceof HTMLFormElement)) {
        throw new TypeError(`不正な HTML Document ${this}`);
    }
    const devIDE = this['dev-id'];
    if (!(devIDE instanceof HTMLInputElement)) {
        throw new TypeError(`不正な HTML Document ${devIDE}`);
    }
    const partnerIDE = this['partner-id'];
    if (!(partnerIDE instanceof HTMLInputElement)) {
        throw new TypeError(`不正な HTML Document ${partnerIDE}`);
    }
    const devNumE = this['dev-num'];
    if (!(devNumE instanceof HTMLInputElement)) {
        throw new TypeError(`不正なフィーム入力 ${devNumE}`);
    }
    const pwE = this['tmp-pw'];
    if (!(pwE instanceof HTMLInputElement)) {
        throw new TypeError(`不正なフィーム入力 ${pwE}`);
    }
    const isupdating = isUpdating();
    const publish = await Dev.initSeedNegotiation(pwE.value, devIDE.value, partnerIDE.value, parseInt(devNumE.value), isupdating);
    // updating を行い始めたら、update toggle を diabled にする
    if (isupdating) {
        const sw = window.document.getElementById('seed-updating');
        if (!(sw instanceof HTMLInputElement)) {
            throw new TypeError(`不正な HTML Document ${sw}`);
        }
        sw.disabled = true;
    }
    // ネゴシエート中の値を公開する
    const publishAreas = window.document.getElementById('seed-nego-publish');
    if (publishAreas &&
        publishAreas instanceof HTMLFormElement &&
        publishAreas['ciphertext'] instanceof HTMLInputElement) {
        publishAreas['ciphertext'].value = publish;
    }
    // ネゴシエート中の方に移る
    window.location.href = '#seed-nego';
});
// ネゴシエート中の結果をクリップボードにコピーする
window.document.getElementById('seed-nego-publish')?.addEventListener('submit', function (e) {
    e.preventDefault();
    if (!(this instanceof HTMLFormElement)) {
        throw new TypeError(`不正な HTML Document ${this}`);
    }
    const txt = this['ciphertext'];
    if (!(txt instanceof HTMLInputElement)) {
        throw TypeError(`不正な HTML Document ${txt}`);
    }
    navigator.clipboard.writeText(txt.value);
});
// 相方から受け取った値を元にシードネゴシエートの計算を行う
window.document.getElementById('seed-nego-form')?.addEventListener('submit', async function (e) {
    e.preventDefault();
    // DOM チェック
    if (!(this instanceof HTMLFormElement)) {
        throw new TypeError(`不正な HTML Document ${this}`);
    }
    const ciphertextE = this['ciphertext'];
    if (!(ciphertextE instanceof HTMLInputElement)) {
        throw new TypeError(`不正な HTML Document ${ciphertextE}`);
    }
    // 計算の実体
    const { completion, ciphertext } = await Dev.seedNegotiating(ciphertextE.value, isUpdating());
    ciphertextE.value = '';
    // 計算結果を公開する
    const publishAreas = window.document.getElementById('seed-nego-publish');
    if (publishAreas &&
        publishAreas instanceof HTMLFormElement &&
        publishAreas['ciphertext'] instanceof HTMLInputElement) {
        publishAreas['ciphertext'].value = ciphertext;
    }
    // このデバイスでネゴシエートの計算が完了すればその旨を表示する。
    if (completion) {
        const completionSection = window.document.getElementById('seed-nego-complition');
        if (completionSection) {
            completionSection.hidden = false;
        }
        // シードの更新を行なった場合は その旨を表示する。
        if (isUpdating()) {
            const p = window.document.getElementById('seed-nego-complition-updated');
            if (p) {
                p.hidden = false;
            }
        }
    }
});
// サービスへこのデバイスを使ってアクセスする
window.document.getElementById('svc-access')?.addEventListener('submit', async function (e) {
    const log = (text) => {
        const footer = window.document.getElementById('svc-footer');
        if (footer == null) {
            throw new TypeError(`不正な HTML Document ${footer}`);
        }
        const p = window.document.createElement('p');
        p.textContent = text;
        footer.append(p);
    };
    e.preventDefault();
    // DOM チェック
    if (!(e instanceof SubmitEvent) || !(e.submitter instanceof HTMLButtonElement)) {
        throw new TypeError(`不正な HTML Document ${e}`);
    }
    // DOM チェック
    if (!(this instanceof HTMLFormElement)) {
        throw new TypeError(`不正な HTML Document ${this}`);
    }
    const svcIDE = this['svc-id'];
    if (!(svcIDE instanceof HTMLSelectElement)) {
        throw new TypeError(`不正な HTML Document ${svcIDE}`);
    }
    const nameE = this['user-name'];
    if (!(nameE instanceof HTMLInputElement)) {
        throw new TypeError(`不正な HTML Document ${nameE}`);
    }
    // アクセスを試みる
    const accessReqMessage = { username: nameE.value };
    const accessResp = await fetch(`${origin}/${svcIDE.value}/access`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(accessReqMessage),
    });
    if (accessResp.status !== 200) {
        log(`${svcIDE.value} へのアクセス要求でstatus(${accessResp.status})のエラー`);
        return;
    }
    const accessRespMessage = await accessResp.json();
    if (!isStartAuthnResponseMessage(accessRespMessage)) {
        log(`${svcIDE.value} へのアクセス要求で不正なレスポンスボディエラー`);
        return;
    }
    // アカウント新規登録を試みる
    if (e.submitter.name === 'register') {
        if ('creds' in accessRespMessage) {
            log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})にアカウント登録済みです`);
            return;
        }
        const r = await Dev.register({ id: svcIDE.value, ...accessRespMessage });
        const regReqMessage = {
            username: nameE.value,
            ...r,
        };
        const regResp = await fetch(`${origin}/${svcIDE.value}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(regReqMessage),
        });
        if (regResp.status !== 200) {
            log(`${svcIDE.value} へのアカウント新規登録要求でstatus(${accessResp.status})のエラー`);
            return;
        }
        registeredUsers[svcIDE.value]?.push(nameE.value) ??
            (registeredUsers[svcIDE.value] = [nameE.value]);
        log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})にアカウント登録完了!`);
        return;
    }
    else if (e.submitter.name === 'login') {
        if (!('creds' in accessRespMessage)) {
            log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value}) に対して登録済みではない`);
            return;
        }
        let a;
        try {
            a = await Dev.authn({ id: svcIDE.value, ...accessRespMessage }, accessRespMessage.ovkm);
        }
        catch {
            // 登録済みクレデンシャルが見つからんのでシームレスな登録を試みる
            const r = await Dev.register({ id: svcIDE.value, ...accessRespMessage }, accessRespMessage.ovkm);
            const regReqMessage = {
                username: nameE.value,
                ...r,
            };
            const regResp = await fetch(`${origin}/${svcIDE.value}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(regReqMessage),
            });
            if (regResp.status !== 200) {
                log(`${svcIDE.value} へのクレデンシャル追加登録要求でstatus(${accessResp.status})のエラー`);
                return;
            }
            log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})にこのデバイスのクレデンシャルを追加登録完了!`);
            return;
        }
        const authnReqMessage = {
            username: nameE.value,
            ...a,
        };
        const authnResp = await fetch(`${origin}/${svcIDE.value}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(authnReqMessage),
        });
        if (authnResp.status !== 200) {
            log(`${svcIDE.value} へのログイン要求でstatus(${accessResp.status})のエラー`);
            return;
        }
        log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})にこのデバイスでログイン成功！`);
    }
    else {
        throw new TypeError(`不正な HTML Document ${e.submitter}`);
    }
});
window.addEventListener('beforeunload', async function () {
    for (const [svcID, users] of Object.entries(registeredUsers)) {
        if (!users) {
            continue;
        }
        for (const user of users) {
            await fetch(`${origin}/${svcID}/reset`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: user }),
            });
        }
    }
});
