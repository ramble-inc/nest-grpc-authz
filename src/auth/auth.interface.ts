import { ModuleMetadata, Type } from '@nestjs/common';
import { Metadata } from 'grpc';

export interface Claim {
  token_use: string;
  auth_time: number;
  iss: string;
  exp: number;
  aud: string;
}

export interface MetadataWithClaim extends Metadata {
  claim: Claim;
}

export interface AuthModuleOptions {
  readonly issuerUri: string;
  readonly clientId: string;
  readonly jwksUri: string;
}

export interface AuthModuleOptionsFactory {
  createAuthModuleOptions(): Promise<AuthModuleOptions> | AuthModuleOptions;
}

export interface AuthModuleAsyncOptions
  extends Pick<ModuleMetadata, 'imports'> {
  useFactory?: (
    ...args: any[]
  ) => Promise<AuthModuleOptions> | AuthModuleOptions;
  useClass?: Type<AuthModuleOptionsFactory>;
  inject?: Type<any>[];
}

export const AUTH_OPTIONS = 'AUTH_OPTIONS';
