import { BASE64URL, HexStr2Uint8Array, Uint8Array2HexStr } from 'utility';
import { RandUint8Array } from './random';

type InfinitePoint = 'O';
const isInfinitePoint = (arg: unknown): arg is InfinitePoint => arg === 'O';
type FinitePoint = { x: bigint; y: bigint };

type Point = FinitePoint | InfinitePoint;

/**
 * SEC1#2.2.1 Elliptic Curves over F_p
 * bigint は暗号処理に向かないため、本番運用は避けるべきである。
 * c.f.) https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt#cryptography
 */
class PCurve {
  constructor(private a: bigint, private b: bigint, public p: bigint) {}

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

  isPoint(P: Point): boolean {
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
    const lambda = mul(p2.y - p1.y, inv(p2.x - p1.x, this.p), this.p);
    const x3 = mod(dbl(lambda, this.p) - p1.x - p2.x, this.p);
    const y3 = mod(mul(lambda, p1.x - x3, this.p) - p1.y, this.p);
    return { x: x3, y: y3 };
  }

  // 有限点の2倍を計算する。
  private doubleFinitePoint(p: FinitePoint): FinitePoint {
    const lambda = mul(3n * dbl(p.x, this.p) + this.a, inv(2n * p.y, this.p), this.p);
    const x3 = mod(dbl(lambda, this.p) - 2n * p.x, this.p);
    const y3 = mod(mul(lambda, p.x - x3, this.p) - p.y, this.p);
    return { x: x3, y: y3 };
  }
}
const mod = (a: bigint, n: bigint): bigint => {
  const ans = a % n;
  return ans < 0 ? ans + n : ans;
};
const mul = (a: bigint, b: bigint, n: bigint): bigint => mod(a * b, n);
const dbl = (a: bigint, n: bigint): bigint => mod(a * a, n);

// 法 n のもと、元 a の逆元を返す関数。逆元がなければエラー。
// inputs: a,n: 整数 (BigInt)
// output: a^(-1) mod n があればそれを返す。
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

export type KeyPairPublic = FinitePoint;

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
      const len = T.n.toString(16).length;
      const d_u8a = RandUint8Array(len / 2);
      d = BigInt('0x' + Uint8Array2HexStr(d_u8a, len / 2));
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
    const x = BASE64URL(HexStr2Uint8Array(this.Q.x.toString(16), 32));
    const y = BASE64URL(HexStr2Uint8Array(this.Q.y.toString(16), 32));
    if (isPublic) {
      return { kty: 'EC', crv: this.T.name.jwk, x, y };
    }
    const d = BASE64URL(HexStr2Uint8Array(this.d.toString(16), 32));
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
