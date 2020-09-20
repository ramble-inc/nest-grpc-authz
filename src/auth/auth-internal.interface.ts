import { Claim } from './auth.interface';

export interface ClaimVerifyRequest {
  readonly token?: string;
}

export interface ClaimVerifyResult {
  readonly claim?: Claim;
  readonly isValid: boolean;
  readonly error?: Error;
}

export interface TokenHeader {
  kid: string;
  alg: string;
}

export interface PublicKey {
  alg: string;
  e: string;
  kid: string;
  kty: string;
  n: string;
  use: string;
}

export interface PublicKeyMeta {
  instance: PublicKey;
  pem: string;
}

export interface PublicKeys {
  keys: PublicKey[];
}

export interface MapOfKidToPublicKey {
  [key: string]: PublicKeyMeta;
}
