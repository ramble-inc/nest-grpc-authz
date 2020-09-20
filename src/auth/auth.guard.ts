import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';
import { ClaimVerifyRequest } from './auth-internal.interface';
import { AuthService } from './auth.service';
import { MetadataWithClaim } from './auth.interface';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // get authorization header
    const metadata = context.switchToRpc().getContext<MetadataWithClaim>();
    if (!metadata) return false;

    const authHeader = metadata.get('authorization');
    if (!authHeader) return false;

    return this.authService
      .validate({
        token: authHeader.toString(),
      } as ClaimVerifyRequest)
      .then((value) => {
        if (value.error) {
          console.log(value.error);
          return false;
        }

        // set claim into metadata
        metadata.claim = value.claim;
        return value.isValid;
      });
  }
}
