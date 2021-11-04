import { newSeed } from 'seed';
import { UTF8 } from 'utility';

(async () => {
  const svcID = 'auth.example.com';

  console.log('デバイス間でシードの共有を始めます。');
  const seedA = newSeed();
  // DeviceA
  const dhkeyA = await (async () => {
    const seed = seedA;
    const dhkey = await seed.startKeyAgreement();
    return dhkey;
  })();

  const seedB = newSeed();
  // DeviceB
  const dhkeyB = await (async () => {
    const seed = seedB;
    const dhkey = await seed.startKeyAgreement();
    return dhkey;
  })();

  // DeviceA
  await (async (dhkey) => {
    const seed = seedA;
    const isSucceeded = await seed.agree(dhkey);
    if (isSucceeded) {
      console.log('デバイスA は デバイス B とのシード共有に成功');
    } else {
      throw new EvalError(`ネゴ失敗`);
    }
  })(dhkeyB);

  // DeviceB
  await (async (dhkey) => {
    const seed = seedB;
    const isSucceeded = await seed.agree(dhkey);
    if (isSucceeded) {
      console.log('デバイスB は デバイス A とのシード共有に成功');
    } else {
      throw new EvalError(`ネゴ失敗`);
    }
  })(dhkeyA);

  //  DeviceA
  console.log('デバイスAでサービスに登録する');
  const { ovk, mac } = await (async () => {
    const seed = seedA;

    const r = UTF8('ABCDEFGHIJKL');
    const ovk = await seed.deriveOVK(r);

    const mac = await seed.macOVK(r, svcID);
    return { ovk, mac };
  })();

  // auth.example.com
  console.log('サービスは Ownership Verification Key を保存する');
  const authSvcDB = { ovk };

  // DeviceB
  console.log('デバイスBでサービスに登録する');
  const { cred, sig } = await (async (ovk, mac) => {
    const seed = seedB;
    const isValid = await seed.verifyOVK(ovk, svcID, mac);
    if (!isValid) {
      throw new EvalError(`seed.verifyOVK failed`);
    }
    const cred = UTF8('Dummy Credential');
    const sig = await seed.signOVK(ovk, cred);
    return { cred, sig };
  })(ovk, mac);

  // auth.example.com
  console.log('サービスはクレデンシャルの検証を OVK を使って行う');
  await (async (cred, sig) => {
    const pk_api = await window.crypto.subtle.importKey(
      'jwk',
      authSvcDB.ovk.toJWK(),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const isValid = await window.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pk_api,
      sig,
      cred
    );
    if (isValid) {
      console.log('サービスはデバイスB のクレデンシャル がデバイスA の OVK で検証できた');
    } else {
      console.log('失敗');
    }
  })(cred, sig);
})();
