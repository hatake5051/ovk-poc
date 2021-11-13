'use strict';

var fs = require('fs');
var http = require('http');

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
 * 文字列を UTF8 バイトエンコードする。(string to Uint8Array)
 */
function UTF8(STRING) {
    const encoder = new TextEncoder();
    return encoder.encode(STRING);
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

const SHA256 = async (m) => {
    const dgst = await RuntimeUtility.subtle.digest('SHA-256', m);
    return new Uint8Array(dgst);
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

function newService(id) {
    return new Service(id);
}
class Service {
    constructor(id) {
        this.id = id;
        this.db = {};
        this.challengeDB = {};
    }
    async startAuthn(name) {
        const challenge = RandUint8Array(32);
        this.challengeDB[name] = [BASE64URL(challenge)];
        const cm = this.db[name];
        if (!cm) {
            return { challenge_b64u: BASE64URL(challenge) };
        }
        return { challenge_b64u: BASE64URL(challenge), ...cm.getCreds() };
    }
    async register(name, cred, ovkm) {
        const challenge_b64u = this.challengeDB[name].pop();
        if (!challenge_b64u) {
            return false;
        }
        // cred のアテステーションを検証する.
        // 面倒なので アテステーションキーの検証は考慮していない
        const pk_atts = await ECPubKey.fromJWK(cred.atts.key);
        if (!(await pk_atts.verify(CONCAT(BASE64URL_DECODE(challenge_b64u), UTF8(JSON.stringify(cred.jwk))), BASE64URL_DECODE(cred.atts.sig_b64u)))) {
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
        const ovk = await ECPubKey.fromJWK(cm.getOVK());
        if (!(await ovk.verify(UTF8(JSON.stringify(cred.jwk)), BASE64URL_DECODE(ovkm.sig_b64u)))) {
            // OVK を使ってクレデンシャルの検証に失敗
            return false;
        }
        return cm.add(cred.jwk);
    }
    async authn(name, cred_jwk, sig_b64u, updating) {
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
    async update(name, update_b64u, ovkm_next) {
        const cm = this.db[name];
        if (!cm) {
            return false;
        }
        const ovk = await ECPubKey.fromJWK(cm.getOVK());
        if (!(await ovk.verify(UTF8(JSON.stringify(ovkm_next.ovk_jwk)), BASE64URL_DECODE(update_b64u)))) {
            return false;
        }
        return cm.addUpdating(ovkm_next.ovk_jwk, ovkm_next.r_b64u, ovkm_next.mac_b64u);
    }
    async delete(name) {
        this.db[name] = undefined;
        return;
    }
}
class CredManager {
    constructor(creds, ovkm, next) {
        this.creds = creds;
        this.ovkm = ovkm;
        this.next = next;
    }
    static init(cred_jwk, ovkm) {
        return new CredManager([{ jwk: cred_jwk, ovk: ovkm.ovk_jwk }], ovkm);
    }
    add(cred_jwk, ovk_jwk) {
        const ovk = ovk_jwk ?? this.getOVK();
        this.creds.push({ jwk: cred_jwk, ovk });
        return true;
    }
    addUpdating(ovk_jwk, r_b64u, mac_b64u) {
        if (!this.next) {
            this.next = [];
        }
        if (!this.next.some((next) => equalECPubJWK(next.ovk_jwk, ovk_jwk))) {
            this.next.push({ ovk_jwk, r_b64u, mac_b64u });
        }
        return true;
    }
    getCreds() {
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
    isCred(cred_jwk) {
        return this.creds.some((c) => equalECPubJWK(c.jwk, cred_jwk));
    }
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
    obj[svc] = newService(svc);
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
