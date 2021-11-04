import { newSeedDeriver } from 'seed';
import { UTF8 } from 'utility';

(async () => {
  const svcID = 'auth.example.com';

  //  DeviceA
  console.log('一台めのデバイスで登録する');
  const { ovk, mac } = await (async () => {
    const seed = newSeedDeriver();

    const r = UTF8('ABCDEFGHIJKL');
    const ovk = await seed.deriveOVK(r);

    const mac = await seed.macOVK(r, svcID);
    return { ovk, mac };
  })();

  // auth.example.com
  console.log('Ownership Verification Key をサービスは保存する');
  const authSvcDB = { ovk };

  // DeviceB
  console.log('2台めのデバイスで登録する');
  const { cred, sig } = await (async (ovk, mac) => {
    const seed = newSeedDeriver();
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
    console.log(isValid);
  })(cred, sig);
})();
