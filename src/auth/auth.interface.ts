export interface ClaimVerifyRequest {
  readonly token?: string;
}

export interface ClaimVerifyResult {
  readonly userName: string;
  readonly clientId: string;
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

export interface Claim {
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  username: string;
  client_id: string;
}
