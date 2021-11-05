import { ECPubJWK, ECPubKey } from 'key';
import { newSeed, Seed } from 'seed';
import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';

(async () => {
  const svcIDs: Record<string, string> = {
    svc1: 'svc1.example',
    svc2: 'svc2.example',
    svc3: 'svc3.example',
    svc4: 'svc4.example',
    svc5: 'svc5.example',
    svc6: 'svc6.example',
    svc7: 'svc7.example',
    svc8: 'svc8.example',
    svc9: 'svc9.example',
    svc10: 'svc10.example',
  };
  type Device = { seed: Seed; epk?: ECPubJWK };

  const DeviceA: Device = {
    seed: newSeed(),
  };
  const DeviceB: Device = {
    seed: newSeed(),
  };
  const SvcDB: Record<
    string,
    Record<
      string,
      { ovk_jwk: ECPubJWK; mac_b64u: string; creds: { cred_utf8: string; sig_b64u: string }[] }
    >
  > = {
    svc1: {},
    svc2: {},
    svc3: {},
    svc4: {},
    svc5: {},
    svc6: {},
    svc7: {},
    svc8: {},
    svc9: {},
    svc10: {},
  };

  console.group('シードの共有 between Device A and Device B');

  // DeviceA
  await (async () => {
    const seed = DeviceA.seed;
    const dhkey = await seed.startKeyAgreement();
    console.log('Device A でシードの共有を開始');
    DeviceB.epk = dhkey.toJWK();
  })();

  // DeviceB
  await (async () => {
    const seed = DeviceB.seed;
    const dhkey = await seed.startKeyAgreement();
    console.log('Device B でシードの共有を開始');
    DeviceA.epk = dhkey.toJWK();
  })();

  console.log('DH公開鍵をやりとり between Device A and B');
  // DeviceA
  await (async () => {
    const seed = DeviceA.seed;
    if (!DeviceA.epk) {
      throw new EvalError(`Epheral PubKey が届いていない`);
    }
    const isSucceeded = await seed.agree(ECPubKey.fromJWK(DeviceA.epk));
    if (isSucceeded) {
      console.log('Device A は Device B とのシード共有に成功');
    } else {
      throw new EvalError(`ネゴ失敗`);
    }
  })();

  // DeviceB
  await (async () => {
    const seed = DeviceB.seed;
    if (!DeviceB.epk) {
      throw new EvalError(`Epheral PubKey が届いていない`);
    }
    const isSucceeded = await seed.agree(ECPubKey.fromJWK(DeviceB.epk));
    if (isSucceeded) {
      console.log('Device B は Device A とのシード共有に成功');
    } else {
      throw new EvalError(`ネゴ失敗`);
    }
  })();
  console.groupEnd();

  for (const svc in svcIDs) {
    console.group(`アカウント新規登録 @ Device A to ${svc}`);
    //  DeviceA
    await (async () => {
      const cred = UTF8(`Dummy Credential in DevA for ${svc}`);

      const seed = DeviceA.seed;
      const r = window.crypto.getRandomValues(new Uint8Array(16));
      const ovk = await seed.deriveOVK(r);
      const mac = await seed.macOVK(r, svcIDs[svc]);

      const sig = await seed.signOVK(ovk, cred);

      SvcDB[svc]['alice'] = {
        ovk_jwk: ovk.toJWK(),
        mac_b64u: BASE64URL(mac),
        creds: [{ cred_utf8: UTF8_DECODE(cred), sig_b64u: BASE64URL(sig) }],
      };
    })();

    // svc1.example
    console.log(`${svc} は Credential と Ownership Verification Key を保存する`);
    console.groupEnd();

    console.group(`クレデンシャルのシームレスな登録 @ Device B to ${svc}`);
    // DeviceB
    await (async () => {
      const cred = UTF8(`Dummy Credential in DevB for ${svc}`);

      const seed = DeviceB.seed;
      const { ovk_jwk, mac_b64u } = SvcDB[svc]['alice'];
      const ovk = ECPubKey.fromJWK(ovk_jwk);
      const isValid = await seed.verifyOVK(ovk, svcIDs[svc], BASE64URL_DECODE(mac_b64u));
      if (!isValid) {
        throw new EvalError(`seed.verifyOVK failed`);
      }

      const sig = await seed.signOVK(ovk, cred);

      SvcDB[svc]['alice'].creds.push({ cred_utf8: UTF8_DECODE(cred), sig_b64u: BASE64URL(sig) });
    })();

    // svc1.example
    console.log(`${svc} はクレデンシャルの検証を OVK を使って行う`);
    await (async () => {
      const { ovk_jwk, creds } = SvcDB[svc]['alice'];
      const pk_api = await window.crypto.subtle.importKey(
        'jwk',
        ovk_jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );
      const { cred_utf8, sig_b64u } = creds[creds.length - 1];
      const isValid = await window.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pk_api,
        BASE64URL_DECODE(sig_b64u),
        UTF8(cred_utf8)
      );
      if (isValid) {
        console.log(`${svc} はデバイスB のクレデンシャル がデバイスA の OVK で検証できた`);
      } else {
        console.log('失敗');
      }
    })();
    console.log(`${svc} は Credential と Ownership Verification Key を保存する`);
    console.groupEnd();
  }
  console.log('デバイスA', DeviceA);
  console.log('デバイスB', DeviceB);
  console.log('サービス', SvcDB);
  for (const svc in SvcDB) {
    const db = SvcDB[svc]['alice'];
    console.log(
      db.ovk_jwk,
      db.creds.map((e) => e.cred_utf8)
    );
  }
})();
