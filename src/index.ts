import { ec } from 'elliptic';

const key = new ec('p256').genKeyPair();
console.log(key.getPrivate('hex'), key.getPublic('hex'));
