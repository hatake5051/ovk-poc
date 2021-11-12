import { readFile } from 'fs';
import { createServer } from 'http';
import { newService, Service } from 'service';
import {
  isAuthnRequestMessage,
  isRegistrationRequestMessage,
  isStartAuthnRequestMessage,
} from './message';

const svcList = ['svc1', 'svc2', 'svc3'] as const;
const Services: Record<typeof svcList[number], Service> = svcList.reduce((obj, svc) => {
  obj[svc] = newService(svc);
  return obj;
}, {} as Record<string, Service>);

const server = createServer(async (req, resp) => {
  // クライアント一式（静的ファイル）を返す。
  if (['/', '/index.html', '/client.js', '/pico.min.css'].includes(req.url ?? '')) {
    const filePath = './publish' + (!req.url || req.url === '/' ? '/index.html' : req.url);
    let contentType: string;
    if (filePath.endsWith('.html')) {
      contentType = 'text/html';
    } else if (filePath.endsWith('.js')) {
      contentType = 'text/javascript';
    } else if (filePath.endsWith('.css')) {
      contentType = 'text/css';
    } else {
      contentType = 'application/octet-stram';
    }
    readFile(filePath, (err, content) => {
      if (err) {
        resp.writeHead(500);
        resp.end('Sorry, check with the site admin for error: ' + err.code + ' ..\n');
        resp.end();
        console.log(`${req.url}: error with 500`);
      } else {
        resp.writeHead(200, { 'Content-Type': contentType });
        resp.end(content, 'utf-8');
        console.log(`${req.url}: return the static file`);
      }
    });
    return;
  }
  // サービスとしてユーザ登録 or ログインを処理する
  if (['/svc'].some((p) => req.url?.startsWith(p))) {
    let svc: typeof svcList[number];
    if (req.url?.startsWith('/svc1')) {
      svc = 'svc1';
    } else if (req.url?.startsWith('/svc2')) {
      svc = 'svc2';
    } else if (req.url?.startsWith('/svc3')) {
      svc = 'svc3';
    } else {
      resp.writeHead(500, { 'Content-Type': 'application/json' });
      resp.end(JSON.stringify({ err: `no such svc request-url: ${req.url}` }));
      console.log(`error with 500`);
      console.groupEnd();
      return;
    }
    let action: 'register' | 'login' | 'access';
    if (req.url?.endsWith('/register')) {
      action = 'register';
    } else if (req.url?.endsWith('/login')) {
      action = 'login';
    } else if (req.url?.endsWith('/access')) {
      action = 'access';
    } else {
      resp.writeHead(500, { 'Content-Type': 'application/json' });
      resp.end(JSON.stringify({ err: `no such action request-url: ${req.url}` }));
      console.log(`${req.url}: error with 500`);
      return;
    }
    const Svc = Services[svc];
    req.setEncoding('utf8');
    req.on('data', async (chunk) => {
      const data: unknown = JSON.parse(chunk);
      switch (action) {
        case 'access': {
          if (!isStartAuthnRequestMessage(data)) {
            resp.writeHead(401, { 'Content-Type': 'application/json' });
            resp.end(JSON.stringify({ err: `formatting error: ${req.url}` }));
            console.log(`${req.url}: error with 401`);
            return;
          }
          const r = await Svc.startAuthn(data.username);
          resp.writeHead(200, { 'Content-Type': 'application/json' });
          resp.end(JSON.stringify(r));
          console.log(`${req.url}:\n  req: ${JSON.stringify(data)}\n  resp: ${JSON.stringify(r)}`);
          return;
        }
        case 'register': {
          if (!isRegistrationRequestMessage(data)) {
            resp.writeHead(401, { 'Content-Type': 'application/json' });
            resp.end(JSON.stringify({ err: `formatting error: ${req.url}` }));
            console.log(`${req.url}:: error with 401`);
            return;
          }
          const r = await Svc.register(data.username, data.cred, data.ovkm);
          resp.writeHead(200, { 'Content-Type': 'application/json' });
          resp.end(JSON.stringify(r));
          console.log(`${req.url}:\n  req: ${JSON.stringify(data)}\n  resp: ${JSON.stringify(r)}`);
          return;
        }
        case 'login': {
          if (!isAuthnRequestMessage(data)) {
            resp.writeHead(401, { 'Content-Type': 'application/json' });
            resp.end(JSON.stringify({ err: `formatting error: ${req.url}` }));
            console.log(`${req.url}: error with 401`);
            return;
          }
          const r = await Svc.authn(data.username, data.cred_jwk, data.sig_b64u, data.updating);
          resp.writeHead(200, { 'Content-Type': 'application/json' });
          resp.end(JSON.stringify(r));
          console.log(`${req.url}:\n  req: ${JSON.stringify(data)}\n  resp: ${JSON.stringify(r)}`);
          return;
        }
      }
    });
    return;
  }

  resp.writeHead(404);
  resp.end();
  console.log(`${req.url}: error with 404`);
});

server.listen(8080);
