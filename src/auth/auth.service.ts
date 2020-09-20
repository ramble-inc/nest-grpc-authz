import { HttpService, Inject, Injectable } from '@nestjs/common';
import { promisify } from 'util';
import { JWK } from 'jwk-to-pem';
import * as jsonwebtoken from 'jsonwebtoken';
import * as jwkToBuffer from 'jwk-to-pem';
import { AUTH_OPTIONS, AuthModuleOptions, Claim } from './auth.interface';
import {
  ClaimVerifyRequest,
  ClaimVerifyResult,
  MapOfKidToPublicKey,
  PublicKeyMeta,
  PublicKeys,
  TokenHeader,
} from './auth-internal.interface';

@Injectable()
export class AuthService {
  cacheKeys: MapOfKidToPublicKey | undefined;

  readonly verifyPromised: (
    token: string,
    key: string,
  ) => Promise<Claim> = promisify(jsonwebtoken.verify.bind(jsonwebtoken));

  constructor(
    @Inject(AUTH_OPTIONS) private readonly options: AuthModuleOptions,
    private readonly httpService: HttpService,
  ) {}

  async validate(request: ClaimVerifyRequest): Promise<ClaimVerifyResult> {
    let result: ClaimVerifyResult;
    try {
      // check jwt sections
      const { token } = request;
      const tokenSections = (token || '').split('.');
      AuthService.checkValidation(tokenSections);

      // check kid
      const headerJSON = Buffer.from(tokenSections[0], 'base64').toString(
        'utf8',
      );
      const header = JSON.parse(headerJSON) as TokenHeader;
      const keys = await this.getPublicKeys(this.options.jwksUri);
      const key = keys[header.kid];
      AuthService.checkKid(key);

      // check expiration and issuer and audience
      const claim = await this.verifyPromised(token, key.pem);
      AuthService.checkClaim(
        claim,
        this.options.issuerUri,
        this.options.clientId,
      );
      result = {
        claim,
        isValid: true,
      };
    } catch (error) {
      result = {
        error: error as Error,
        isValid: false,
      };
    }
    return result;
  }

  private async getPublicKeys(jwksUri: string): Promise<MapOfKidToPublicKey> {
    if (!this.cacheKeys) {
      const publicKeys = await this.httpService
        .get<PublicKeys>(jwksUri)
        .toPromise();
      this.cacheKeys = publicKeys.data.keys.reduce((agg, current) => {
        const pem = jwkToBuffer(current as JWK);
        return {
          ...agg,
          [current.kid]: {
            instance: current,
            pem,
          },
        };
      }, {} as MapOfKidToPublicKey);
    }
    return this.cacheKeys;
  }

  private static checkValidation(tokenSections: string[]): void {
    if (tokenSections.length < 2) {
      throw new Error('requested token is invalid');
    }
  }

  private static checkKid(key: PublicKeyMeta): void {
    if (key === undefined) {
      throw new Error('claim made for unknown kid');
    }
  }

  private static checkClaim(
    claim: unknown,
    issuerUri: string,
    clientId: string,
  ): void {
    if (AuthService.isClaim(claim)) {
      AuthService.checkExpiration(claim);
      AuthService.checkIssuer(claim, issuerUri);
      AuthService.checkClientId(claim, clientId);
      AuthService.checkUsage(claim);
    } else {
      throw new Error('claim is invalid');
    }
  }

  private static checkExpiration(claim: Claim): void {
    const currentSeconds = Math.floor(new Date().valueOf() / 1000);
    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
      throw new Error('claim is expired or invalid');
    }
  }

  private static checkIssuer(claim: Claim, issuerUri: string): void {
    if (claim.iss !== issuerUri) {
      throw new Error('claim issuer is invalid');
    }
  }

  private static checkClientId(claim: Claim, clientId: string): void {
    if (claim.aud !== clientId) {
      throw new Error('claim client_id is invalid');
    }
  }

  private static checkUsage(claim: Claim): void {
    if (claim.token_use !== 'id') {
      throw new Error('claim use is not id');
    }
  }

  private static isClaim(value: unknown): value is Claim {
    return (
      typeof value === 'object' &&
      typeof (value as Claim).token_use === 'string' &&
      typeof (value as Claim).auth_time === 'number' &&
      typeof (value as Claim).exp === 'number' &&
      typeof (value as Claim).aud === 'string' &&
      typeof (value as Claim).iss === 'string'
    );
  }
}
