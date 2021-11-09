import { ECPubJWK, isECPubJWK } from 'key';
import { isObject } from 'utility';

type ovkm = {
  ovk_jwk: ECPubJWK;
  r_b64u: string;
  mac_b64u: string;
};

const isovkm = (arg: unknown): arg is ovkm =>
  isObject<ovkm>(arg) &&
  isECPubJWK(arg.ovk_jwk) &&
  typeof arg.r_b64u === 'string' &&
  typeof arg.mac_b64u === 'string';

export type StartAuthnRequestMessage = {
  username: string;
};

export const isStartAuthnRequestMessage = (arg: unknown): arg is StartAuthnRequestMessage =>
  isObject<StartAuthnRequestMessage>(arg) && typeof arg.username === 'string';

export type StartAuthnResponseMessage =
  | {
      challenge_b64u: string;
    }
  | {
      challenge_b64u: string;
      creds: ECPubJWK[];
      ovkm: ovkm & { next?: ovkm[] };
    };

export const isStartAuthnResponseMessage = (arg: unknown): arg is StartAuthnResponseMessage =>
  (isObject<{ challenge_b64u: string }>(arg) && typeof arg.challenge_b64u === 'string') ||
  (isObject<{
    challenge_b64u: string;
    creds: ECPubJWK[];
    ovkm: ovkm & { next?: ovkm[] };
  }>(arg) &&
    typeof arg.challenge_b64u === 'string' &&
    Array.isArray(arg.creds) &&
    arg.creds.every(isECPubJWK) &&
    isObject<ovkm & { next?: ovkm[] }>(arg.ovkm) &&
    (!arg.ovkm.next || (Array.isArray(arg.ovkm.next) && arg.ovkm.next.every(isovkm))) &&
    isovkm(arg.ovkm));

export type RegistrationRequestMessage = {
  username: string;
  cred: {
    jwk: ECPubJWK;
    atts: {
      sig_b64u: string;
      key: ECPubJWK;
    };
  };
  ovkm: ovkm | { sig_b64u: string };
};

export const isRegistrationRequestMessage = (arg: unknown): arg is RegistrationRequestMessage =>
  isObject<RegistrationRequestMessage>(arg) &&
  typeof arg.username === 'string' &&
  isObject<RegistrationRequestMessage['cred']>(arg.cred) &&
  isECPubJWK(arg.cred.jwk) &&
  isObject<RegistrationRequestMessage['cred']['atts']>(arg.cred.atts) &&
  typeof arg.cred.atts.sig_b64u === 'string' &&
  isECPubJWK(arg.cred.atts.key) &&
  (isovkm(arg.ovkm) ||
    (isObject<{ sig_b64u: string }>(arg.ovkm) && typeof arg.ovkm.sig_b64u === 'string'));

export type AuthnRequestMessage = {
  username: string;
  cred_jwk: ECPubJWK;
  sig_b64u: string;
  updating?: {
    update_b64u: string;
    ovkm: ovkm;
  };
};

export const isAuthnRequestMessage = (arg: unknown): arg is AuthnRequestMessage =>
  isObject<AuthnRequestMessage>(arg) &&
  typeof arg.username === 'string' &&
  isECPubJWK(arg.cred_jwk) &&
  typeof arg.sig_b64u === 'string' &&
  (!arg.updating ||
    (isObject<NonNullable<AuthnRequestMessage['updating']>>(arg.updating) &&
      typeof arg.updating?.update_b64u === 'string' &&
      isovkm(arg.updating.ovkm)));
