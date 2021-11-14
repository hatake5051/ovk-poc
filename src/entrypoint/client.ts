import { Device } from 'device';
import { newSeed } from 'seed';
import {
  AuthnRequestMessage,
  isStartAuthnResponseMessage,
  RegistrationRequestMessage,
  StartAuthnRequestMessage,
} from './message';

const origin = 'http://localhost:8080';

let Dev: Device;
const registeredUsers: Record<string, string[] | undefined> = {};

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
const isUpdating = (): boolean => {
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
    const publish = await Dev.initSeedNegotiation(
      pwE.value,
      devIDE.value,
      partnerIDE.value,
      parseInt(devNumE.value),
      isupdating
    );
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
  const { completion, ciphertext } = await Dev.seedNegotiating(ciphertextE.value, isUpdating());
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
  const log = (text: string) => {
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
  const accessReqMessage: StartAuthnRequestMessage = { username: nameE.value };
  const accessResp = await fetch(`${origin}/${svcIDE.value}/access`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(accessReqMessage),
  });
  if (accessResp.status !== 200) {
    log(`${svcIDE.value} へのアクセス要求でstatus(${accessResp.status})のエラー`);
    return;
  }
  const accessRespMessage: unknown = await accessResp.json();
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
    const regReqMessage: RegistrationRequestMessage = {
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
    const regRespMessage: unknown = await regResp.json();
    if (typeof regRespMessage !== 'boolean') {
      log(`${svcIDE.value} へのアカウント新規登録要求で不正なレスポンスボディエラー`);
      return;
    }
    if (!regRespMessage) {
      log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})へのアカウント登録に失敗`);
      return;
    }
    registeredUsers[svcIDE.value]?.push(nameE.value) ??
      (registeredUsers[svcIDE.value] = [nameE.value]);
    log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})にアカウント登録完了!`);
    return;
  } // ログインを行う場合
  else if (e.submitter.name === 'login') {
    if (!('creds' in accessRespMessage)) {
      log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value}) に対して登録済みではない`);
      return;
    }
    let a: ReturnType<typeof Dev.authn> extends Promise<infer P> ? P : never;
    try {
      a = await Dev.authn({ id: svcIDE.value, ...accessRespMessage }, accessRespMessage.ovkm);
    } catch {
      // 登録済みクレデンシャルが見つからんのでシームレスな登録を試みる
      let r: ReturnType<typeof Dev.register> extends Promise<infer P> ? P : never;
      try {
        r = await Dev.register({ id: svcIDE.value, ...accessRespMessage }, accessRespMessage.ovkm);
      } catch {
        log(
          `ユーザ(${nameE.value}) はサービス(${svcIDE.value}) に対して登録済みだが OVK が一致しない`
        );
        return;
      }
      const regReqMessage: RegistrationRequestMessage = {
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
      const regRespMessage: unknown = await regResp.json();
      if (typeof regRespMessage !== 'boolean') {
        log(`${svcIDE.value} へのアカウント新規登録要求で不正なレスポンスボディエラー`);
        return;
      }
      if (!regRespMessage) {
        log(
          `ユーザ(${nameE.value}) はサービス(${svcIDE.value})にこのデバイスのクレデンシャルを追加登録に失敗`
        );
        return;
      }

      log(
        `ユーザ(${nameE.value}) はサービス(${svcIDE.value})にこのデバイスのクレデンシャルを追加登録完了!`
      );
      return;
    }
    const authnReqMessage: AuthnRequestMessage = {
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
    const authnRespMessage: unknown = await authnResp.json();
    if (typeof authnRespMessage !== 'boolean') {
      log(`${svcIDE.value} へのログイン要求で不正なレスポンスボディエラー`);
      return;
    }
    if (!authnRespMessage) {
      log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})にこのデバイスでログイン失敗`);
      return;
    }
    log(`ユーザ(${nameE.value}) はサービス(${svcIDE.value})にこのデバイスでログイン成功！`);
  } else {
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
