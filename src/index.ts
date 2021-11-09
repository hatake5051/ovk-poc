import { Device } from 'device';
import { newSeed } from 'seed';

let Dev: Device;

// Dev を初期化する
window.document.getElementById('dev-name')?.addEventListener('submit', async function (e) {
  e.preventDefault();
  if (!(e instanceof SubmitEvent) || !(e.submitter instanceof HTMLButtonElement)) {
    throw TypeError(`不正な HTML Document ${e}`);
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
    const publish = await Dev.initSeedNegotiation(
      pwE.value,
      devIDE.value,
      partnerIDE.value,
      parseInt(devNumE.value)
    );
    // ネゴシエート中の値を公開する
    const publishAreas = window.document.getElementById('seed-nego-publish');
    if (
      publishAreas &&
      publishAreas instanceof HTMLFormElement &&
      publishAreas['ciphertext'] instanceof HTMLInputElement
    ) {
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
  const { completion, ciphertext } = await Dev.seedNegotiating(ciphertextE.value);
  ciphertextE.value = '';
  // 計算結果を公開する
  const publishAreas = window.document.getElementById('seed-nego-publish');
  if (
    publishAreas &&
    publishAreas instanceof HTMLFormElement &&
    publishAreas['ciphertext'] instanceof HTMLInputElement
  ) {
    publishAreas['ciphertext'].value = ciphertext;
  }
  // このデバイスでネゴシエートの計算が完了すればその旨を表示する。
  if (completion) {
    const completionSection = window.document.getElementById('seed-nego-complition');
    if (completionSection) {
      completionSection.hidden = false;
    }
  }
});

window.document.getElementById('svc-access')?.addEventListener('submit', function (e) {
  e.preventDefault();
  if (!(e instanceof SubmitEvent) || !(e.submitter instanceof HTMLInputElement)) {
    throw TypeError(`不正な HTML Document ${e}`);
  }
  console.log(e.submitter?.name);
});

// (async () => {
//   // Service の用意
//   const svcIDs: Record<string, string> = {
//     svc1: 'svc1.example',
//     svc2: 'svc2.example',
//     svc3: 'svc3.example',
//   };
//   const Services: Record<string, Service> = {};
//   for (const svc in svcIDs) {
//     Services[svc] = newService(svcIDs[svc]);
//   }
//   // Device の用意
//   const devList = ['devA', 'devB'] as const;
//   const partnerDevName = (devname: typeof devList[number]) => {
//     // multiparty DH 鍵共有を行う際の相方情報を含める
//     // device List をソートして相方のデバイスを決める (インデックスが一つ前のデバイス);
//     const partner_idx = devList.indexOf(devname);
//     const partnerDevName = devList[partner_idx === 0 ? devList.length - 1 : partner_idx - 1];
//     return partnerDevName;
//   };
//   const x = {} as Record<string, Device>;
//   for (const devname of devList) {
//     x[devname] = await Device.gen(devname, newSeed());
//   }
//   const Devices: Record<typeof devList[number], Device> = x;

//   for (const isUpdating of [false, true]) {
//     console.group(isUpdating ? 'シードの更新を行う' : 'シードの共有を行う');
//     await (async () => {
//       // デバイスでシードをネゴシエートするときに、公開する情報を置いておく場所
//       const bbs: Record<typeof devList[number], string> = devList.reduce((obj, devname) => {
//         obj[devname] = '';
//         return obj;
//       }, {} as Record<string, string>);

//       // まずは各デバイスで seed ネゴシエーションの初期化を行う;
//       for (const devname of devList) {
//         console.log(`Dev(${devname}) initiate negotiation...`);
//         const Dev = Devices[devname];
//         // id はネゴシエーション中に一意に識別できたら良い
//         const ciphertext = await Dev.initSeedNegotiation(
//           `dummy-password${isUpdating ? '-updating' : ''}`,
//           `${devname}-tmp${isUpdating ? '-updating' : ''}`,
//           `${partnerDevName(devname)}-tmp${isUpdating ? '-updating' : ''}`,
//           devList.length,
//           isUpdating
//         );
//         // 初期 DH 公開鍵を公開する
//         bbs[devname] = ciphertext;
//       }
//       // シードの共有が完了していないデバイスリスト
//       let dl = [...devList];
//       // シードの共有のプロセスを実行するデバイス（インデックス）
//       let i = -1;
//       // 全てのデバイスでシードの共有が終わるまで以下を繰り返す。
//       while (dl.length !== 0) {
//         // // 最短で行くなら次のデバイスを触るのが良い
//         const r = (i + 1) % dl.length;
//         i = r;
//         const devname = dl[i];
//         console.log(`Dev(${devname}) process negotiation...`);
//         await (async () => {
//           // 相方の公開 DH 値をとってきて自身の秘密鍵と一緒に計算する
//           const { completion, ciphertext } = await Devices[devname].seedNegotiating(
//             bbs[partnerDevName(devname)],
//             isUpdating
//           );
//           // 計算した結果を公開する
//           bbs[devname] = ciphertext;
//           if (completion) {
//             // 完了した場合は dl から消去する。インデックスを新しい配列の長さと揃えるために -1 している。
//             dl = dl.filter((n) => n !== devname);
//             i--;
//             console.log(`${devname} はシードの共有完了, remains: ${dl}`);
//           }
//         })();
//       }
//       console.log(`ネゴシエート中に公開された値`, bbs);
//       console.log(`全てのデバイスでシードの共有が完了した`);
//     })();
//     console.groupEnd();

//     // username を alice としてサービスにアカウント登録して、利用する
//     const username = 'alice';
//     for (const svcname in svcIDs) {
//       const Svc = Services[svcname];
//       for (const devname of [...devList, ...devList]) {
//         const Dev = Devices[devname];
//         await (async () => {
//           console.group(`User(${username}) は Dev(${devname}) を使って Svc(${svcname}) にアクセス`);
//           // サービスにログイン要求を行なった場合のレスポンスに応じて、アカウント登録済みかどうか判断できる
//           const a = await Svc.startAuthn(username);
//           if (!('creds' in a)) {
//             // 一つもクレデンシャルを登録していない -> アカウント登録済みではない
//             console.log(`User(${username}) は Svc(${svcname}) にアカウントを登録していない`);
//             const { cred, ovkm } = await Dev.register({ id: svcname, ...a });
//             // クレデンシャルと OVK を登録
//             const isRegistered = await Svc.register(username, cred, ovkm);
//             if (isRegistered) {
//               console.log(`Dev(${devname}) で Svc(${svcname}) に新規登録(OVK と Cred の登録)`);
//             } else {
//               throw new EvalError(`Svc(${svcname}) はアカウント新規登録に失敗`);
//             }
//             console.groupEnd();
//             return;
//           } else {
//             // クレデンシャルを登録時み -> アカウントは登録済み
//             console.log(`User(${username}) は Svc(${svcname}) にアカウントを登録済み`);
//             let da: ReturnType<typeof Dev.authn> extends Promise<infer P> ? P : never;
//             try {
//               // Device で認証操作を行なった場合、一致するクレデンシャルがなければこのデバイスは未登録であると判断できる
//               da = await Dev.authn({ id: svcname, ...a }, a.ovkm);
//             } catch {
//               // 登録済みクレデンシャルがデバイスにない -> OVK を利用したクレデンシャル登録
//               console.log(
//                 `User(${username}) は Dev(${devname}) を Svc(${svcname}) に登録していない`
//               );

//               const { cred, ovkm } = await Dev.register({ id: svcname, ...a }, a.ovkm);
//               const isRegistered = await Svc.register(username, cred, ovkm);
//               if (isRegistered) {
//                 console.log(`Dev(${devname}) で Svc(${svcname}) に追加登録(Cred の登録)`);
//               } else {
//                 throw new EvalError(`Svc(${svcname}) は Dev(${devname}) の追加登録に失敗`);
//               }
//               console.groupEnd();
//               return;
//             }
//             // 一致するクレデンシャルがある -> ログインする
//             console.log(`User(${username}) は Dev(${devname}) を Svc(${svcname}) に登録している`);
//             const isAuthned = await Svc.authn(username, da.cred_jwk, da.sig_b64u, da.updating);
//             if (isAuthned) {
//               console.log(`Dev(${devname}) で Svc(${svcname}) にログイン`);
//             } else {
//               throw new EvalError(`Dev(${devname}) を使った ${svcname} へのログイン失敗`);
//             }
//             console.groupEnd();
//             return;
//           }
//         })();
//       }
//     }
//   }

//   console.group('Results');
//   for (const devname of devList) {
//     console.log(`Dev(${devname})`, Devices[devname]);
//   }
//   for (const svcname in svcIDs) {
//     console.log(`Svc(${svcname})`, Services[svcname]);
//   }
//   console.groupEnd();
// })();
