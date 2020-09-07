import {
  CanActivate,
  ExecutionContext,
  HttpService,
  Inject,
  Injectable,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import {
  Claim,
  ClaimVerifyRequest,
  ClaimVerifyResult,
  MapOfKidToPublicKey,
  PublicKeyMeta,
  PublicKeys,
  TokenHeader,
} from '@/auth/auth.interface';
import { promisify } from 'util';
import * as jsonwebtoken from 'jsonwebtoken';
import { Metadata } from 'grpc';
import { JWK } from 'jwk-to-pem';
import jwkToBuffer = require('jwk-to-pem');

@Injectable()
export class AuthGuard implements CanActivate {
  cacheKeys: MapOfKidToPublicKey | undefined;

  readonly cognitoPoolId = process.env.COGNITO_POOL_ID || '';

  readonly cognitoIssuer = `https://cognito-idp.us-east-2.amazonaws.com/${this.cognitoPoolId}`;

  readonly verifyPromised = promisify(jsonwebtoken.verify.bind(jsonwebtoken));

  constructor(
    @Inject('HttpService') private readonly httpService: HttpService,
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const metadata = context.switchToRpc().getContext<Metadata>();
    // get authorization header
    const authHeader = metadata.get('authorization');

    return this.handler({
      token: authHeader.toString(),
    } as ClaimVerifyRequest).then((value) => {
      if (value.error) {
        return false;
      }

      return value.isValid;
    });
  }

  async getPublicKeys(): Promise<MapOfKidToPublicKey> {
    if (!this.cacheKeys) {
      const url = `${this.cognitoIssuer}/.well-known/jwks.json`;
      const publicKeys = await this.httpService
        .get<PublicKeys>(url)
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

  async handler(request: ClaimVerifyRequest): Promise<ClaimVerifyResult> {
    let result: ClaimVerifyResult;
    try {
      const { token } = request;
      const tokenSections = (token || '').split('.');
      AuthGuard.checkValidation(tokenSections);
      const headerJSON = Buffer.from(tokenSections[0], 'base64').toString(
        'utf8',
      );
      const header = JSON.parse(headerJSON) as TokenHeader;
      const keys = await this.getPublicKeys();
      const key = keys[header.kid];
      AuthGuard.checkKid(key);
      const claim = (await this.verifyPromised(token, key.pem)) as Claim;
      AuthGuard.checkExpiration(claim);
      this.checkIssuer(claim);
      AuthGuard.checkUsage(claim);
      result = {
        userName: claim.username,
        clientId: claim.client_id,
        isValid: true,
      };
    } catch (error) {
      result = {
        userName: '',
        clientId: '',
        error: error as Error,
        isValid: false,
      };
    }
    return result;
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

  private static checkExpiration(claim: Claim): void {
    const currentSeconds = Math.floor(new Date().valueOf() / 1000);
    if (currentSeconds > claim.exp || currentSeconds < claim.auth_time) {
      throw new Error('claim is expired or invalid');
    }
  }

  private checkIssuer(claim: Claim): void {
    if (claim.iss !== this.cognitoIssuer) {
      throw new Error('claim issuer is invalid');
    }
  }

  private static checkUsage(claim: Claim): void {
    if (claim.token_use !== 'id') {
      throw new Error('claim use is not id');
    }
  }
}
