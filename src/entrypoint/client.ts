import { Device } from 'device';
import { newSeed } from 'seed';
import {
  AuthnRequestMessage,
  isStartAuthnResponseMessage,
  RegistrationRequestMessage,
  StartAuthnRequestMessage,
} from './message';

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

window.document.getElementById('svc-access')?.addEventListener('submit', async function (e) {
  e.preventDefault();
  if (!(e instanceof SubmitEvent) || !(e.submitter instanceof HTMLButtonElement)) {
    throw TypeError(`不正な HTML Document ${e}`);
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
  const accessReqMessage: StartAuthnRequestMessage = { username: nameE.value };

  const accessResp = await fetch(`http://localhost:8080/${svcIDE.value}/access`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(accessReqMessage),
  });
  if (accessResp.status !== 200) {
    console.log('fetch error');
    return;
  }
  const accessRespMessage: unknown = await accessResp.json();
  if (!isStartAuthnResponseMessage(accessRespMessage)) {
    console.log(`fetch error`, accessRespMessage);
    return;
  }

  if (e.submitter.name === 'register') {
    if ('creds' in accessRespMessage) {
      throw new EvalError(
        `usename${nameE.value} はこのサービス${svcIDE.value}に対して登録済みです`
      );
    }
    const r = await Dev.register({ id: svcIDE.value, ...accessRespMessage });
    const regReqMessage: RegistrationRequestMessage = {
      username: nameE.value,
      ...r,
    };
    const regResp = await fetch(`http://localhost:8080/${svcIDE.value}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(regReqMessage),
    });
    if (regResp.status !== 200) {
      console.log('アカウント新規登録に失敗', regReqMessage, regResp);
      throw new EvalError(`アカウント新規登録に失敗 ${regReqMessage}`);
    }
    console.log('アカウント新規登録完了!');
  } else if (e.submitter.name === 'login') {
    if (!('creds' in accessRespMessage)) {
      throw new EvalError(
        `username(${nameE.value}) はこのサービス(${svcIDE.value}) に対して登録済みではない`
      );
    }
    let a: ReturnType<typeof Dev.authn> extends Promise<infer P> ? P : never;
    try {
      a = await Dev.authn({ id: svcIDE.value, ...accessRespMessage }, accessRespMessage.ovkm);
    } catch {
      // 登録済みクレデンシャルが見つからん
      const r = await Dev.register(
        { id: svcIDE.value, ...accessRespMessage },
        accessRespMessage.ovkm
      );
      const regReqMessage: RegistrationRequestMessage = {
        username: nameE.value,
        ...r,
      };
      const regResp = await fetch(`http://localhost:8080/${svcIDE.value}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(regReqMessage),
      });
      if (regResp.status !== 200) {
        console.log('クレデンシャル追加登録に失敗', regReqMessage, regResp);
        throw new EvalError(`クレデンシャル追加登録に失敗 ${regReqMessage}`);
      }
      console.log('クレデンシャル追加登録完了!');
      return;
    }
    const authnReqMessage: AuthnRequestMessage = {
      username: nameE.value,
      ...a,
    };
    const authnResp = await fetch(`http://localhost:8080/${svcIDE.value}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authnReqMessage),
    });
    if (authnResp.status !== 200) {
      console.log('アカウントの認証に失敗', authnReqMessage, authnResp);
      throw new EvalError(`アカウントログインに失敗 ${authnReqMessage}`);
    }
    console.log('ログイン完了');
  } else {
    throw new TypeError(`不正な HTML Document ${e.submitter}`);
  }
});
