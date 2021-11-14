import { BASE64URL, HexStr2Uint8Array, Uint8Array2HexStr } from 'utility';
import { RandUint8Array } from './random';

/**
 * 楕円曲線の無限遠点を表現する。
 */
type InfinitePoint = 'O';
const isInfinitePoint = (arg: unknown): arg is InfinitePoint => arg === 'O';
/**
 * 楕円曲線上の点を表現する。
 */
type FinitePoint = { x: bigint; y: bigint };

/**
 * EC では楕円曲線上のてんに無限遠点を加えたものを考える。
 */
type Point = FinitePoint | InfinitePoint;

/**
 * SEC1#2.2.1 Elliptic Curves over F_p を実装する。
 * E(F_p): y^2 = x^3 + ax + b (mod p)なので、パラメータは a,b,p
 * 実装に当たっては bigint を利用しているが、bigint は暗号処理に向かないため、本番運用は避けるべきである。
 * c.f.) https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography
 */
class PCurve {
  constructor(private a: bigint, private b: bigint, public p: bigint) {}

  /**
   * k * p を行う
   * @param p 楕円曲線上の点
   * @param k 整数 in [1,p-1]
   * @returns p を k 回足した結果 k*p
   */
  exp(p: Point, k: bigint): Point {
    const absk = k < 0n ? -k : k;
    const k_bin = absk.toString(2);
    let ans: Point = 'O';
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
  isPoint(P: Point): boolean {
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

  private mod(a: bigint): bigint {
    return mod(a, this.p);
  }

  private mul(a: bigint, b: bigint): bigint {
    return mul(a, b, this.p);
  }

  private dbl(a: bigint): bigint {
    return dbl(a, this.p);
  }

  private inv(a: bigint): bigint {
    return inv(a, this.p);
  }

  /**
   * 楕円曲線上の２点の加算を定義する
   */
  add(p1: Point, p2: Point): Point {
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
  double(p: Point): Point {
    if (isInfinitePoint(p)) {
      return 'O';
    }
    return this.doubleFinitePoint(p);
  }

  // 異なる有限点の足し算を計算する。
  private addDiffFinitePoints(p1: FinitePoint, p2: FinitePoint): FinitePoint {
    if (p1.x === p2.x) {
      throw new EvalError(`addDiffPoints function は異なる２点の加算しか行えません`);
    }
    const lambda = this.mul(p2.y - p1.y, this.inv(p2.x - p1.x));
    const x3 = this.mod(this.dbl(lambda) - p1.x - p2.x);
    const y3 = this.mod(this.mul(lambda, p1.x - x3) - p1.y);
    return { x: x3, y: y3 };
  }

  // 有限点の2倍を計算する。
  private doubleFinitePoint(p: FinitePoint): FinitePoint {
    const lambda = this.mul(3n * this.dbl(p.x) + this.a, this.inv(2n * p.y));
    const x3 = this.mod(this.dbl(lambda) - 2n * p.x);
    const y3 = this.mod(this.mul(lambda, p.x - x3) - p.y);
    return { x: x3, y: y3 };
  }
}

/**
 * a (mod n)
 */
const mod = (a: bigint, n: bigint): bigint => {
  const ans = a % n;
  return ans < 0 ? ans + n : ans;
};

/**
 * a * b (mod n)
 */
const mul = (a: bigint, b: bigint, n: bigint): bigint => mod(a * b, n);

/**
 * a^2 (mod n)
 */
const dbl = (a: bigint, n: bigint): bigint => mod(a * a, n);

/**
 * a^(-1) (mod n) で逆元がなければエラー
 */
function inv(a: bigint, n: bigint): bigint {
  // 拡張ユークリッドの誤除法
  // inputs: a,b: 正整数 (BigInt)
  // output: ax + by = d (d は a と b の最大公約数)
  //         {d: BigInt, a: BigInt, b: BigInt}
  function ex_euclid(a: bigint, b: bigint): { d: bigint; x: bigint; y: bigint } {
    if (b === 0n) {
      // ax + 0*y = d の一つの解を計算する
      return { d: a, x: 1n, y: 0n };
    }
    // a = bq + r を代入した b(qx + r) + rx = d が分かれば
    const z = ex_euclid(b, a % b);
    // ax + by = d は計算できる
    return { d: z.d, x: z.y, y: z.x - (a / b) * z.y };
  }
  while (a < 0) a += n;
  const z = ex_euclid(a, n);
  if (z.d != 1n) {
    throw new Error(`法 ${n} のもとで ${a} の逆元はない`);
  }
  return z.x % n;
}

/**
 * KeyPair の公開鍵を表現する。
 */
export type KeyPairPublic = FinitePoint;

/**
 * 楕円曲線の鍵ペアを実装する。
 */
export class KeyPair {
  private constructor(private T: DomainParams, private d: bigint, private Q: FinitePoint) {}

  /**
   * SEC1#3.2.1 EC Key Pair Generation Primitive
   * @param T 楕円曲線のドメインパラメータ
   * @param d 秘密鍵
   * @returns 鍵ペア
   */
  static gen(T: DomainParams, d?: bigint): KeyPair {
    if (!d) {
      const d_u8a = RandUint8Array(T.n.toString(16).length / 2);
      d = BigInt('0x' + Uint8Array2HexStr(d_u8a));
    } else if (d < 0n || T.n <= d) {
      throw new TypeError(`秘密鍵のサイズが不適切`);
    }
    const Q = T.crv.exp(T.G, d);
    if (isInfinitePoint(Q)) {
      throw new EvalError(`d が不適切`);
    }
    return new KeyPair(T, d, Q);
  }

  computeDH(Q: KeyPairPublic): KeyPairPublic {
    const c = this.T.crv.exp(Q, this.d);
    if (isInfinitePoint(c)) {
      throw new EvalError(`DHの計算結果が無限遠点です`);
    }
    return c;
  }

  isValidate(): boolean {
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

type DomainParams = {
  name: {
    jwk: string;
  };
  crv: PCurve;
  G: Point;
  n: bigint;
  h: bigint;
};

/**
 * secp256r1 のドメインパラメータ
 */
export const secp256r1: DomainParams = {
  name: { jwk: 'P-256' },
  crv: new PCurve(
    BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
    BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
    BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff')
  ),
  G: {
    x: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
    y: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
  },
  n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
  h: 1n,
};
