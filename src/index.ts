import { ECPubJWK, ECPubKey } from 'key';
import { newSeed, Seed } from 'seed';
import { newService, Service } from 'service';
import { BASE64URL, BASE64URL_DECODE, UTF8, UTF8_DECODE } from 'utility';

(async () => {
  const svcIDs: Record<string, string> = {
    svc1: 'svc1.example',
    svc2: 'svc2.example',
    svc3: 'svc3.example',
  };
  const Services: Record<string, Service> = {};
  for (const svc in svcIDs) {
    Services[svc] = newService(svcIDs[svc]);
  }

  type Device = { seed: Seed; creds: Record<string, string | undefined>; epk?: ECPubJWK };
  const devList = ['devA', 'devB'];
  const Devices: Record<string, Device> = {};
  for (const devname of devList) {
    Devices[devname] = { seed: newSeed(), creds: {} };
  }

  console.group('シードの共有 between Device A and Device B');
  for (const devname of devList) {
    await (async () => {
      const seed = Devices[devname].seed;
      const dhkey = await seed.startAgreement();
      console.log(`Dev(${devname}) でシードの共有を開始'`);
      for (const other of devList) {
        if (other !== devname) {
          Devices[other].epk = await dhkey.toJWK();
        }
      }
    })();
  }
  console.log('DH公開鍵をやりとり between Device A and B');
  for (const devname of devList) {
    const Dev = Devices[devname];
    await (async () => {
      const seed = Dev.seed;
      if (!Dev.epk) {
        throw new EvalError(`Dev(${devname}) にEpheral PubKey が届いていない`);
      }
      const isSucceeded = await seed.agree(ECPubKey.fromJWK(Dev.epk));
      if (isSucceeded) {
        console.log(`Dev(${devname}) でシード生成に成功`);
      } else {
        throw new EvalError(`ネゴ失敗`);
      }
      Dev.epk = undefined;
    })();
  }
  console.groupEnd();

  const username = 'alice';
  for (const svc in svcIDs) {
    const Svc = Services[svc];
    for (const devname of [...devList, ...devList]) {
      await (async () => {
        console.group(`user(${username}) は Dev(${devname}) を使って svc(${svc}) にアクセス`);
        const Dev = Devices[devname];
        let challenge: Uint8Array;
        let creds_utf8: string[];
        let ovkm: {
          ovk_jwk: ECPubJWK;
          r_b64u: string;
          mac_b64u: string;
          next?: {
            ovk_jwk: ECPubJWK;
            r_b64u: string;
            mac_b64u: string;
          }[];
        };
        try {
          const x = await Svc.startAuthn(username);
          challenge = BASE64URL_DECODE(x.challenge_b64u);
          creds_utf8 = x.creds_utf8;
          ovkm = x.ovkm;
        } catch (e) {
          console.log(`user(${username}) は svc(${svc}) にアカウントを登録していない`);
          console.log(`Device(${devname}) で svc(${svc}) にアカウント新規登録`);
          // クレデンシャルの生成
          const cred = UTF8(`Dummy Credential in ${devname} for ${svc}`);
          Dev.creds[svc] = UTF8_DECODE(cred);
          // OVK の生成
          const seed = Dev.seed;
          const r = window.crypto.getRandomValues(new Uint8Array(16));
          const ovk = await seed.deriveOVK(r);
          const mac = await seed.macOVK(ovk, r, svcIDs[svc]);
          // クレデンシャルと OVK を登録
          const isRegistered = await Svc.register(username, UTF8_DECODE(cred), {
            ovk_jwk: await ovk.toJWK(),
            mac_b64u: BASE64URL(mac),
            r_b64u: BASE64URL(r),
          });
          if (isRegistered) {
            console.log(`${svc} は Credential と Ownership Verification Key を保存した`);
          } else {
            throw new EvalError(`${svc} はアカウント新規登録に失敗`);
          }
          console.groupEnd();
          return;
        }
        console.log(`user(${username}) は svc(${svc}) にアカウントを登録済み`);
        let cred_utf8 = creds_utf8.find((c) => c === Dev.creds[svc]);
        if (!cred_utf8) {
          console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録していない`);
          console.log(`Device(${devname}) で svc(${svc}) にクレデンシャルのシームレスな登録`);
          // cred を生成して challenge に署名する (TODO: 必要か？)
          cred_utf8 = `Dummy Credential in ${devname} for ${svc}`;
          Dev.creds[svc] = cred_utf8;
          const sig_cred = new Uint8Array(
            await window.crypto.subtle.sign(
              'HMAC',
              await window.crypto.subtle.importKey(
                'raw',
                UTF8(cred_utf8),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
              ),
              challenge
            )
          );
          // r の検証と OVK の導出
          const seed = Dev.seed;
          if (
            !(await seed.verifyOVK(
              ECPubKey.fromJWK(ovkm.ovk_jwk),
              BASE64URL_DECODE(ovkm.r_b64u),
              svcIDs[svc],
              BASE64URL_DECODE(ovkm.mac_b64u)
            ))
          ) {
            throw new EvalError(`seed.verifyOVK failed`);
          }
          const sig_ovk = await seed.signOVK(
            ECPubKey.fromJWK(ovkm.ovk_jwk),
            BASE64URL_DECODE(ovkm.r_b64u),
            UTF8(cred_utf8)
          );
          console.log(`${svc} はクレデンシャルの検証を OVK を使って行う`);
          const isRegistered = await Svc.seamlessRegister('alice', cred_utf8, BASE64URL(sig_cred), {
            sig_b64u: BASE64URL(sig_ovk),
          });
          if (isRegistered) {
            console.log(`${svc} はデバイスB のクレデンシャル がデバイスA の OVK で検証できた`);
          } else {
            throw new EvalError(`${svc} はDeviceB のアカウント新規登録に失敗`);
          }
          console.groupEnd();
          return;
        }
        console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録している`);
        console.log(`Device(${devname}) で svc(${svc}) にログイン`);
        const seed = Dev.seed;
        let updating:
          | {
              update_b64u: string;
              ovkm: {
                ovk_jwk: ECPubJWK;
                r_b64u: string;
                mac_b64u: string;
              };
            }
          | undefined;
        if (await seed.isUpdating()) {
          console.log(`Dev(${devname}) は svc(${svc}) の OVK を更新する`);
          const seed = Dev.seed;
          if (!ovkm.next) {
            // 誰も Update メッセージを送っていない
            const r = window.crypto.getRandomValues(new Uint8Array(16));
            const ovk = await seed.deriveOVK(r);
            const mac = await seed.macOVK(ovk, r, svcIDs[svc]);
            const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
            updating = {
              update_b64u: BASE64URL(update),
              ovkm: { ovk_jwk: await ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
            };
          } else {
            // Update メッセージが送信されている
            let ov_correct:
              | {
                  ovk_jwk: ECPubJWK;
                  r_b64u: string;
                  mac_b64u: string;
                }
              | undefined;
            for (const ov of ovkm.next) {
              const isVerified = await seed.verifyOVK(
                ECPubKey.fromJWK(ov.ovk_jwk),
                BASE64URL_DECODE(ov.r_b64u),
                svcIDs[svc],
                BASE64URL_DECODE(ov.mac_b64u)
              );
              if (isVerified) {
                ov_correct = ov;
                break;
              }
            }
            if (!ov_correct) {
              // 知らない人が update メッセージを送っている！！！
              const r = window.crypto.getRandomValues(new Uint8Array(16));
              const ovk = await seed.deriveOVK(r);
              const mac = await seed.macOVK(ovk, r, svcIDs[svc]);
              const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
              updating = {
                update_b64u: BASE64URL(update),
                ovkm: {
                  ovk_jwk: await ovk.toJWK(),
                  r_b64u: BASE64URL(r),
                  mac_b64u: BASE64URL(mac),
                },
              };
            } else {
              const update = await seed.update(
                BASE64URL_DECODE(ovkm.r_b64u),
                ECPubKey.fromJWK(ov_correct.ovk_jwk)
              );
              updating = { update_b64u: BASE64URL(update), ovkm: ov_correct };
            }
          }
        }
        // challenge-response 認証
        const sig = new Uint8Array(
          await window.crypto.subtle.sign(
            'HMAC',
            await window.crypto.subtle.importKey(
              'raw',
              UTF8(cred_utf8),
              { name: 'HMAC', hash: 'SHA-256' },
              false,
              ['sign']
            ),
            challenge
          )
        );
        const isAuthned = await Svc.authn('alice', cred_utf8, BASE64URL(sig), updating);
        if (isAuthned) {
          console.log(`Device A を使って ${svc} にログイン成功`);
        } else {
          throw new EvalError(`Device A を使った ${svc} へのログイン失敗`);
        }
        console.groupEnd();
        return;
      })();
    }
  }

  console.group('シードの更新を行います');
  for (const devname of devList) {
    await (async () => {
      const seed = Devices[devname].seed;
      const dhkey = await seed.startAgreement(true);
      console.log(`Dev(${devname}) でシードの更新を開始'`);
      for (const other of devList) {
        if (other !== devname) {
          Devices[other].epk = await dhkey.toJWK();
        }
      }
    })();
  }
  console.log('DH公開鍵をやりとり between Device A and B');
  for (const devname of devList) {
    const Dev = Devices[devname];
    await (async () => {
      const seed = Dev.seed;
      if (!Dev.epk) {
        throw new EvalError(`Dev(${devname}) にEpheral PubKey が届いていない`);
      }
      const isSucceeded = await seed.agree(ECPubKey.fromJWK(Dev.epk));
      if (isSucceeded) {
        console.log(`Dev(${devname}) でシード生成に成功`);
      } else {
        throw new EvalError(`ネゴ失敗`);
      }
      Dev.epk = undefined;
    })();
  }
  console.groupEnd();

  for (const svc in svcIDs) {
    const Svc = Services[svc];
    for (const devname of [...devList, ...devList]) {
      await (async () => {
        console.group(`user(${username}) は Dev(${devname}) を使って svc(${svc}) にアクセス`);
        const Dev = Devices[devname];
        let challenge: Uint8Array;
        let creds_utf8: string[];
        let ovkm: {
          ovk_jwk: ECPubJWK;
          r_b64u: string;
          mac_b64u: string;
          next?: {
            ovk_jwk: ECPubJWK;
            r_b64u: string;
            mac_b64u: string;
          }[];
        };
        try {
          const x = await Svc.startAuthn(username);
          challenge = BASE64URL_DECODE(x.challenge_b64u);
          creds_utf8 = x.creds_utf8;
          ovkm = x.ovkm;
        } catch (e) {
          console.log(`user(${username}) は svc(${svc}) にアカウントを登録していない`);
          console.log(`Device(${devname}) で svc(${svc}) にアカウント新規登録`);
          // クレデンシャルの生成
          const cred = UTF8(`Dummy Credential in ${devname} for ${svc}`);
          Dev.creds[svc] = UTF8_DECODE(cred);
          // OVK の生成
          const seed = Dev.seed;
          const r = window.crypto.getRandomValues(new Uint8Array(16));
          const ovk = await seed.deriveOVK(r);
          const mac = await seed.macOVK(ovk, r, svcIDs[svc]);
          // クレデンシャルと OVK を登録
          const isRegistered = await Svc.register(username, UTF8_DECODE(cred), {
            ovk_jwk: await ovk.toJWK(),
            mac_b64u: BASE64URL(mac),
            r_b64u: BASE64URL(r),
          });
          if (isRegistered) {
            console.log(`${svc} は Credential と Ownership Verification Key を保存した`);
          } else {
            throw new EvalError(`${svc} はアカウント新規登録に失敗`);
          }
          console.groupEnd();
          return;
        }
        console.log(`user(${username}) は svc(${svc}) にアカウントを登録済み`);
        let cred_utf8 = creds_utf8.find((c) => c === Dev.creds[svc]);
        if (!cred_utf8) {
          console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録していない`);
          console.log(`Device(${devname}) で svc(${svc}) にクレデンシャルのシームレスな登録`);
          // cred を生成して challenge に署名する (TODO: 必要か？)
          cred_utf8 = `Dummy Credential in ${devname} for ${svc}`;
          Dev.creds[svc] = cred_utf8;
          const sig_cred = new Uint8Array(
            await window.crypto.subtle.sign(
              'HMAC',
              await window.crypto.subtle.importKey(
                'raw',
                UTF8(cred_utf8),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
              ),
              challenge
            )
          );
          // r の検証と OVK の導出
          const seed = Dev.seed;
          if (
            !(await seed.verifyOVK(
              ECPubKey.fromJWK(ovkm.ovk_jwk),
              BASE64URL_DECODE(ovkm.r_b64u),
              svcIDs[svc],
              BASE64URL_DECODE(ovkm.mac_b64u)
            ))
          ) {
            throw new EvalError(`seed.verifyOVK failed`);
          }
          const sig_ovk = await seed.signOVK(
            ECPubKey.fromJWK(ovkm.ovk_jwk),
            BASE64URL_DECODE(ovkm.r_b64u),
            UTF8(cred_utf8)
          );
          console.log(`${svc} はクレデンシャルの検証を OVK を使って行う`);
          const isRegistered = await Svc.seamlessRegister('alice', cred_utf8, BASE64URL(sig_cred), {
            sig_b64u: BASE64URL(sig_ovk),
          });
          if (isRegistered) {
            console.log(`${svc} はデバイスB のクレデンシャル がデバイスA の OVK で検証できた`);
          } else {
            throw new EvalError(`${svc} はDeviceB のアカウント新規登録に失敗`);
          }
          console.groupEnd();
          return;
        }
        console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録している`);
        console.log(`Device(${devname}) で svc(${svc}) にログイン`);
        const seed = Dev.seed;
        let updating:
          | {
              update_b64u: string;
              ovkm: {
                ovk_jwk: ECPubJWK;
                r_b64u: string;
                mac_b64u: string;
              };
            }
          | undefined;
        if (await seed.isUpdating()) {
          console.log(`Dev(${devname}) はシードを更新している`);
          console.log(`Dev(${devname}) は svc(${svc}) の OVK を更新する`);
          const seed = Dev.seed;
          if (!ovkm.next) {
            // 誰も Update メッセージを送っていない
            console.log(`Dev(${devname}) は svc(${svc}) に対して OVK を新規生成する`);
            const r = window.crypto.getRandomValues(new Uint8Array(16));
            const ovk = await seed.deriveOVK(r);
            const mac = await seed.macOVK(ovk, r, svcIDs[svc]);
            const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
            updating = {
              update_b64u: BASE64URL(update),
              ovkm: { ovk_jwk: await ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
            };
          } else {
            // Update メッセージが送信されている
            let ov_correct:
              | {
                  ovk_jwk: ECPubJWK;
                  r_b64u: string;
                  mac_b64u: string;
                }
              | undefined;
            for (const ov of ovkm.next) {
              const isVerified = await seed.verifyOVK(
                ECPubKey.fromJWK(ov.ovk_jwk),
                BASE64URL_DECODE(ov.r_b64u),
                svcIDs[svc],
                BASE64URL_DECODE(ov.mac_b64u)
              );
              if (isVerified) {
                ov_correct = ov;
                break;
              }
            }
            if (!ov_correct) {
              console.log(
                `違うシードからの OVK が登録されているので Dev(${devname}) は svc(${svc}) に対して OVK を新規生成する`
              );
              // 知らない人が update メッセージを送っている！！！
              const r = window.crypto.getRandomValues(new Uint8Array(16));
              const ovk = await seed.deriveOVK(r);
              const mac = await seed.macOVK(ovk, r, svcIDs[svc]);
              const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
              updating = {
                update_b64u: BASE64URL(update),
                ovkm: {
                  ovk_jwk: await ovk.toJWK(),
                  r_b64u: BASE64URL(r),
                  mac_b64u: BASE64URL(mac),
                },
              };
            } else {
              console.log(
                `Dev(${devname}) は svc(${svc}) に対して同じ OVK の update メッセージを送る`
              );
              const update = await seed.update(
                BASE64URL_DECODE(ovkm.r_b64u),
                ECPubKey.fromJWK(ov_correct.ovk_jwk)
              );
              updating = { update_b64u: BASE64URL(update), ovkm: ov_correct };
            }
          }
        }
        // challenge-response 認証
        const sig = new Uint8Array(
          await window.crypto.subtle.sign(
            'HMAC',
            await window.crypto.subtle.importKey(
              'raw',
              UTF8(cred_utf8),
              { name: 'HMAC', hash: 'SHA-256' },
              false,
              ['sign']
            ),
            challenge
          )
        );
        const isAuthned = await Svc.authn('alice', cred_utf8, BASE64URL(sig), updating);
        if (isAuthned) {
          console.log(`Device A を使って ${svc} にログイン成功`);
        } else {
          throw new EvalError(`Device A を使った ${svc} へのログイン失敗`);
        }
        console.groupEnd();
        return;
      })();
    }
  }

  console.group('Results');
  for (const devname of devList) {
    console.log(`Dev(${devname})`, Devices[devname]);
  }
  console.log('サービス', Services);
  console.groupEnd();
})();
