import { Device } from 'device';
import { newSeed } from 'seed';
import { newService, Service } from 'service';

(async () => {
  // Service の用意
  const svcIDs: Record<string, string> = {
    svc1: 'svc1.example',
    svc2: 'svc2.example',
    svc3: 'svc3.example',
  };
  const Services: Record<string, Service> = {};
  for (const svc in svcIDs) {
    Services[svc] = newService(svcIDs[svc]);
  }
  // Device の用意
  const devList = ['devA', 'devB', 'devC', 'devD'] as const;
  const partnerDevName = (devname: typeof devList[number]) => {
    // multiparty DH 鍵共有を行う際の相方情報を含める
    // device List をソートして相方のデバイスを決める (インデックスが一つ前のデバイス);
    const partner_idx = devList.indexOf(devname);
    const partnerDevName = devList[partner_idx === 0 ? devList.length - 1 : partner_idx - 1];
    return partnerDevName;
  };
  const Devices: Record<typeof devList[number], Device> = devList.reduce((obj, devname) => {
    obj[devname] = new Device(newSeed());
    return obj;
  }, {} as Record<string, Device>);

  console.group('シードの共有を行う');
  await (async () => {
    // デバイスでシードネゴシエートする間、各デバイスで計算した DH 値を公開する場所
    const bbs: Record<typeof devList[number], string> = devList.reduce((obj, devname) => {
      obj[devname] = '';
      return obj;
    }, {} as Record<string, string>);

    // まずは各デバイスで seed ネゴシエーションの初期化を行う;
    for (const devname of devList) {
      // id はネゴシエーション中に一意に識別できたら良い
      const ciphertext = await Devices[devname].initSeedNegotiation(
        'dummy-password',
        `${devname}-tmp`,
        `${partnerDevName(devname)}-tmp`,
        devList.length
      );
      // 初期 DH 公開鍵を公開する
      bbs[devname] = ciphertext;
    }
    // シードの共有が完了していないデバイスリスト
    let dl = [...devList];
    // シードの共有のプロセスを実行するデバイス（インデックス）
    let i = -1;
    // 全てのデバイスでシードの共有が終わるまで以下を繰り返す。
    while (dl.length !== 0) {
      // // 最短で行くなら次のデバイスを触るのが良い
      const r = (i + 1) % dl.length;
      i = r;
      const devname = dl[i];
      console.log(`Dev(${devname}) process negotiation...`);
      await (async () => {
        // 相方の公開 DH 値をとってきて自身の秘密鍵と一緒に計算する
        const { completion, ciphertext } = await Devices[devname].seedNegotiating(
          bbs[partnerDevName(devname)]
        );
        // 計算した結果を公開する
        bbs[devname] = ciphertext;
        if (completion) {
          // 完了した場合は dl から消去する。インデックスを新しい配列の長さと揃えるために -1 している。
          dl = dl.filter((n) => n !== devname);
          i--;
          console.log(`${devname} はシードの共有完了, remains: ${dl}`);
        }
      })();
    }
    console.log(`全てのデバイスでシードの共有が完了した`);
    console.log(`ネゴシエート中の通信路`, bbs);
  })();
  console.groupEnd();

  // const username = 'alice';
  // for (const svc in svcIDs) {
  //   const Svc = Services[svc];
  //   for (const devname of [...devList, ...devList]) {
  //     await (async () => {
  //       console.group(`user(${username}) は Dev(${devname}) を使って svc(${svc}) にアクセス`);
  //       const Dev = Devices[devname];
  //       let challenge: Uint8Array;
  //       let creds_utf8: string[];
  //       let ovkm: {
  //         ovk_jwk: ECPubJWK;
  //         r_b64u: string;
  //         mac_b64u: string;
  //         next?: {
  //           ovk_jwk: ECPubJWK;
  //           r_b64u: string;
  //           mac_b64u: string;
  //         }[];
  //       };
  //       try {
  //         const x = await Svc.startAuthn(username);
  //         challenge = BASE64URL_DECODE(x.challenge_b64u);
  //         creds_utf8 = x.creds_utf8;
  //         ovkm = x.ovkm;
  //       } catch (e) {
  //         console.log(`user(${username}) は svc(${svc}) にアカウントを登録していない`);
  //         console.log(`Device(${devname}) で svc(${svc}) にアカウント新規登録`);
  //         // クレデンシャルの生成
  //         const cred = UTF8(`Dummy Credential in ${devname} for ${svc}`);
  //         Dev.creds[svc] = UTF8_DECODE(cred);
  //         // OVK の生成
  //         const seed = Dev.seed;
  //         const r = window.crypto.getRandomValues(new Uint8Array(16));
  //         const ovk = await seed.deriveOVK(r);
  //         const mac = await seed.macOVK(r, svcIDs[svc]);
  //         // クレデンシャルと OVK を登録
  //         const isRegistered = await Svc.register(username, UTF8_DECODE(cred), {
  //           ovk_jwk: await ovk.toJWK(),
  //           mac_b64u: BASE64URL(mac),
  //           r_b64u: BASE64URL(r),
  //         });
  //         if (isRegistered) {
  //           console.log(`${svc} は Credential と Ownership Verification Key を保存した`);
  //         } else {
  //           throw new EvalError(`${svc} はアカウント新規登録に失敗`);
  //         }
  //         console.groupEnd();
  //         return;
  //       }
  //       console.log(`user(${username}) は svc(${svc}) にアカウントを登録済み`);
  //       let cred_utf8 = creds_utf8.find((c) => c === Dev.creds[svc]);
  //       if (!cred_utf8) {
  //         console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録していない`);
  //         console.log(`Device(${devname}) で svc(${svc}) にクレデンシャルのシームレスな登録`);
  //         // cred を生成して challenge に署名する (TODO: 必要か？)
  //         cred_utf8 = `Dummy Credential in ${devname} for ${svc}`;
  //         Dev.creds[svc] = cred_utf8;
  //         const sig_cred = new Uint8Array(
  //           await window.crypto.subtle.sign(
  //             'HMAC',
  //             await window.crypto.subtle.importKey(
  //               'raw',
  //               UTF8(cred_utf8),
  //               { name: 'HMAC', hash: 'SHA-256' },
  //               false,
  //               ['sign']
  //             ),
  //             challenge
  //           )
  //         );
  //         // r の検証と OVK の導出
  //         const seed = Dev.seed;
  //         if (
  //           !(await seed.verifyOVK(
  //             BASE64URL_DECODE(ovkm.r_b64u),
  //             svcIDs[svc],
  //             BASE64URL_DECODE(ovkm.mac_b64u)
  //           ))
  //         ) {
  //           throw new EvalError(`seed.verifyOVK failed`);
  //         }
  //         const sig_ovk = await seed.signOVK(BASE64URL_DECODE(ovkm.r_b64u), UTF8(cred_utf8));
  //         console.log(`${svc} はクレデンシャルの検証を OVK を使って行う`);
  //         const isRegistered = await Svc.seamlessRegister('alice', cred_utf8, BASE64URL(sig_cred), {
  //           sig_b64u: BASE64URL(sig_ovk),
  //         });
  //         if (isRegistered) {
  //           console.log(`${svc} はデバイスB のクレデンシャル がデバイスA の OVK で検証できた`);
  //         } else {
  //           throw new EvalError(`${svc} はDeviceB のアカウント新規登録に失敗`);
  //         }
  //         console.groupEnd();
  //         return;
  //       }
  //       console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録している`);
  //       console.log(`Device(${devname}) で svc(${svc}) にログイン`);
  //       const seed = Dev.seed;
  //       let updating:
  //         | {
  //             update_b64u: string;
  //             ovkm: {
  //               ovk_jwk: ECPubJWK;
  //               r_b64u: string;
  //               mac_b64u: string;
  //             };
  //           }
  //         | undefined;
  //       if (await seed.isUpdating()) {
  //         console.log(`Dev(${devname}) は svc(${svc}) の OVK を更新する`);
  //         const seed = Dev.seed;
  //         if (!ovkm.next) {
  //           // 誰も Update メッセージを送っていない
  //           const r = window.crypto.getRandomValues(new Uint8Array(16));
  //           const ovk = await seed.deriveOVK(r);
  //           const mac = await seed.macOVK(r, svcIDs[svc]);
  //           const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
  //           updating = {
  //             update_b64u: BASE64URL(update),
  //             ovkm: { ovk_jwk: await ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
  //           };
  //         } else {
  //           // Update メッセージが送信されている
  //           let ov_correct:
  //             | {
  //                 ovk_jwk: ECPubJWK;
  //                 r_b64u: string;
  //                 mac_b64u: string;
  //               }
  //             | undefined;
  //           for (const ov of ovkm.next) {
  //             const isVerified = await seed.verifyOVK(
  //               BASE64URL_DECODE(ov.r_b64u),
  //               svcIDs[svc],
  //               BASE64URL_DECODE(ov.mac_b64u)
  //             );
  //             if (isVerified) {
  //               ov_correct = ov;
  //               break;
  //             }
  //           }
  //           if (!ov_correct) {
  //             // 知らない人が update メッセージを送っている！！！
  //             const r = window.crypto.getRandomValues(new Uint8Array(16));
  //             const ovk = await seed.deriveOVK(r);
  //             const mac = await seed.macOVK(r, svcIDs[svc]);
  //             const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
  //             updating = {
  //               update_b64u: BASE64URL(update),
  //               ovkm: {
  //                 ovk_jwk: await ovk.toJWK(),
  //                 r_b64u: BASE64URL(r),
  //                 mac_b64u: BASE64URL(mac),
  //               },
  //             };
  //           } else {
  //             const update = await seed.update(
  //               BASE64URL_DECODE(ovkm.r_b64u),
  //               ECPubKey.fromJWK(ov_correct.ovk_jwk)
  //             );
  //             updating = { update_b64u: BASE64URL(update), ovkm: ov_correct };
  //           }
  //         }
  //       }
  //       // challenge-response 認証
  //       const sig = new Uint8Array(
  //         await window.crypto.subtle.sign(
  //           'HMAC',
  //           await window.crypto.subtle.importKey(
  //             'raw',
  //             UTF8(cred_utf8),
  //             { name: 'HMAC', hash: 'SHA-256' },
  //             false,
  //             ['sign']
  //           ),
  //           challenge
  //         )
  //       );
  //       const isAuthned = await Svc.authn('alice', cred_utf8, BASE64URL(sig), updating);
  //       if (isAuthned) {
  //         console.log(`Device A を使って ${svc} にログイン成功`);
  //       } else {
  //         throw new EvalError(`Device A を使った ${svc} へのログイン失敗`);
  //       }
  //       console.groupEnd();
  //       return;
  //     })();
  //   }
  // }

  // console.group('シードの更新を行う');
  // await (async () => {
  //   // シード共有する際の DH 公開鍵を一時的に保存するストア
  //   const epk: Record<string, Record<number, ECPubJWK | undefined> | undefined> = {};
  //   // シードの共有が完了していないデバイスリスト
  //   let dl = [...devList];
  //   // シードの共有のプロセスを実行するデバイス（インデックス）
  //   let i = -1;
  //   // 全てのデバイスでシードの共有が終わるまで以下を繰り返す。
  //   while (dl.length !== 0) {
  //     // // 最短で行くなら次のデバイスを触るのが良い (dev.length * 2 -1 でいける)
  //     // const r = (i + 1) % dl.length;
  //     // 操作するデバイスは以前操作していない未完了デバイスのいずれかにしてみた;
  //     const r = Math.floor(Math.random() * dl.length);
  //     if (r === i && dl.length !== 1) {
  //       continue;
  //     }
  //     i = r;
  //     const devname = dl[i];
  //     console.log(`Dev(${devname}) process negotiation...`);
  //     await (async () => {
  //       const seed = Devices[devname].seed;
  //       const { completion, epk: epk_computed } = await seed.negotiate(
  //         { id: devname, devIDs: devList },
  //         epk,
  //         true
  //       );
  //       if (completion) {
  //         // 完了した場合は dl から消去する。インデックスを新しい配列の長さと揃えるために -1 している。
  //         dl = dl.filter((n) => n !== devname);
  //         i--;
  //         console.log(`${devname} はシードの共有完了, remains: ${dl}`);
  //       }
  //       let x = epk[devname];
  //       if (!x) {
  //         x = {};
  //       }
  //       for (const [c, k] of Object.entries(epk_computed)) {
  //         x[parseInt(c)] = k;
  //       }
  //       epk[devname] = x;
  //     })();
  //   }
  //   console.log(`全てのデバイスでシードの共有が完了した`);
  //   console.log(`共有にあたって公開された情報->`, epk);
  // })();
  // console.groupEnd();

  // for (const svc in svcIDs) {
  //   const Svc = Services[svc];
  //   for (const devname of [...devList, ...devList]) {
  //     await (async () => {
  //       console.group(`user(${username}) は Dev(${devname}) を使って svc(${svc}) にアクセス`);
  //       const Dev = Devices[devname];
  //       let challenge: Uint8Array;
  //       let creds_utf8: string[];
  //       let ovkm: {
  //         ovk_jwk: ECPubJWK;
  //         r_b64u: string;
  //         mac_b64u: string;
  //         next?: {
  //           ovk_jwk: ECPubJWK;
  //           r_b64u: string;
  //           mac_b64u: string;
  //         }[];
  //       };
  //       try {
  //         const x = await Svc.startAuthn(username);
  //         challenge = BASE64URL_DECODE(x.challenge_b64u);
  //         creds_utf8 = x.creds_utf8;
  //         ovkm = x.ovkm;
  //       } catch (e) {
  //         console.log(`user(${username}) は svc(${svc}) にアカウントを登録していない`);
  //         console.log(`Device(${devname}) で svc(${svc}) にアカウント新規登録`);
  //         // クレデンシャルの生成
  //         const cred = UTF8(`Dummy Credential in ${devname} for ${svc}`);
  //         Dev.creds[svc] = UTF8_DECODE(cred);
  //         // OVK の生成
  //         const seed = Dev.seed;
  //         const r = window.crypto.getRandomValues(new Uint8Array(16));
  //         const ovk = await seed.deriveOVK(r);
  //         const mac = await seed.macOVK(r, svcIDs[svc]);
  //         // クレデンシャルと OVK を登録
  //         const isRegistered = await Svc.register(username, UTF8_DECODE(cred), {
  //           ovk_jwk: await ovk.toJWK(),
  //           mac_b64u: BASE64URL(mac),
  //           r_b64u: BASE64URL(r),
  //         });
  //         if (isRegistered) {
  //           console.log(`${svc} は Credential と Ownership Verification Key を保存した`);
  //         } else {
  //           throw new EvalError(`${svc} はアカウント新規登録に失敗`);
  //         }
  //         console.groupEnd();
  //         return;
  //       }
  //       console.log(`user(${username}) は svc(${svc}) にアカウントを登録済み`);
  //       let cred_utf8 = creds_utf8.find((c) => c === Dev.creds[svc]);
  //       if (!cred_utf8) {
  //         console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録していない`);
  //         console.log(`Device(${devname}) で svc(${svc}) にクレデンシャルのシームレスな登録`);
  //         // cred を生成して challenge に署名する (TODO: 必要か？)
  //         cred_utf8 = `Dummy Credential in ${devname} for ${svc}`;
  //         Dev.creds[svc] = cred_utf8;
  //         const sig_cred = new Uint8Array(
  //           await window.crypto.subtle.sign(
  //             'HMAC',
  //             await window.crypto.subtle.importKey(
  //               'raw',
  //               UTF8(cred_utf8),
  //               { name: 'HMAC', hash: 'SHA-256' },
  //               false,
  //               ['sign']
  //             ),
  //             challenge
  //           )
  //         );
  //         // r の検証と OVK の導出
  //         const seed = Dev.seed;
  //         if (
  //           !(await seed.verifyOVK(
  //             BASE64URL_DECODE(ovkm.r_b64u),
  //             svcIDs[svc],
  //             BASE64URL_DECODE(ovkm.mac_b64u)
  //           ))
  //         ) {
  //           throw new EvalError(`seed.verifyOVK failed`);
  //         }
  //         const sig_ovk = await seed.signOVK(BASE64URL_DECODE(ovkm.r_b64u), UTF8(cred_utf8));
  //         console.log(`${svc} はクレデンシャルの検証を OVK を使って行う`);
  //         const isRegistered = await Svc.seamlessRegister('alice', cred_utf8, BASE64URL(sig_cred), {
  //           sig_b64u: BASE64URL(sig_ovk),
  //         });
  //         if (isRegistered) {
  //           console.log(`${svc} はデバイスB のクレデンシャル がデバイスA の OVK で検証できた`);
  //         } else {
  //           throw new EvalError(`${svc} はDeviceB のアカウント新規登録に失敗`);
  //         }
  //         console.groupEnd();
  //         return;
  //       }
  //       console.log(`user(${username}) は Dev(${devname}) を svc(${svc}) に登録している`);
  //       console.log(`Device(${devname}) で svc(${svc}) にログイン`);
  //       const seed = Dev.seed;
  //       let updating:
  //         | {
  //             update_b64u: string;
  //             ovkm: {
  //               ovk_jwk: ECPubJWK;
  //               r_b64u: string;
  //               mac_b64u: string;
  //             };
  //           }
  //         | undefined;
  //       if (await seed.isUpdating()) {
  //         console.log(`Dev(${devname}) は svc(${svc}) の OVK を更新する`);
  //         const seed = Dev.seed;
  //         if (!ovkm.next) {
  //           // 誰も Update メッセージを送っていない
  //           const r = window.crypto.getRandomValues(new Uint8Array(16));
  //           const ovk = await seed.deriveOVK(r);
  //           const mac = await seed.macOVK(r, svcIDs[svc]);
  //           const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
  //           updating = {
  //             update_b64u: BASE64URL(update),
  //             ovkm: { ovk_jwk: await ovk.toJWK(), r_b64u: BASE64URL(r), mac_b64u: BASE64URL(mac) },
  //           };
  //         } else {
  //           // Update メッセージが送信されている
  //           let ov_correct:
  //             | {
  //                 ovk_jwk: ECPubJWK;
  //                 r_b64u: string;
  //                 mac_b64u: string;
  //               }
  //             | undefined;
  //           for (const ov of ovkm.next) {
  //             const isVerified = await seed.verifyOVK(
  //               BASE64URL_DECODE(ov.r_b64u),
  //               svcIDs[svc],
  //               BASE64URL_DECODE(ov.mac_b64u)
  //             );
  //             if (isVerified) {
  //               ov_correct = ov;
  //               break;
  //             }
  //           }
  //           if (!ov_correct) {
  //             // 知らない人が update メッセージを送っている！！！
  //             const r = window.crypto.getRandomValues(new Uint8Array(16));
  //             const ovk = await seed.deriveOVK(r);
  //             const mac = await seed.macOVK(r, svcIDs[svc]);
  //             const update = await seed.update(BASE64URL_DECODE(ovkm.r_b64u), ovk);
  //             updating = {
  //               update_b64u: BASE64URL(update),
  //               ovkm: {
  //                 ovk_jwk: await ovk.toJWK(),
  //                 r_b64u: BASE64URL(r),
  //                 mac_b64u: BASE64URL(mac),
  //               },
  //             };
  //           } else {
  //             const update = await seed.update(
  //               BASE64URL_DECODE(ovkm.r_b64u),
  //               ECPubKey.fromJWK(ov_correct.ovk_jwk)
  //             );
  //             updating = { update_b64u: BASE64URL(update), ovkm: ov_correct };
  //           }
  //         }
  //       }
  //       // challenge-response 認証
  //       const sig = new Uint8Array(
  //         await window.crypto.subtle.sign(
  //           'HMAC',
  //           await window.crypto.subtle.importKey(
  //             'raw',
  //             UTF8(cred_utf8),
  //             { name: 'HMAC', hash: 'SHA-256' },
  //             false,
  //             ['sign']
  //           ),
  //           challenge
  //         )
  //       );
  //       const isAuthned = await Svc.authn('alice', cred_utf8, BASE64URL(sig), updating);
  //       if (isAuthned) {
  //         console.log(`Device A を使って ${svc} にログイン成功`);
  //       } else {
  //         throw new EvalError(`Device A を使った ${svc} へのログイン失敗`);
  //       }
  //       console.groupEnd();
  //       return;
  //     })();
  //   }
  // }

  console.group('Results');
  for (const devname of devList) {
    console.log(`Dev(${devname})`, Devices[devname]);
  }
  console.log('サービス', Services);
  console.groupEnd();
})();
