# @ramble-inc/nest-grpc-authz

## Getting Started

### Installation

Using `yarn`

```
yarn add @ramble-inc/nest-authz
```

or using `npm`

```
npm i --save @ramble-inc/nest-authz
```

### Use Guard

#### Set global guard

`AuthGuard` depends on `AuthService` , so import `AuthModule` .

[NOTE] <br>
Do not use `useGlobalGuards()` because cannot inject dependencies to guard. <br>
See https://docs.nestjs.com/guards#binding-guards[NestJS official documents]

```typescript
@Module({
  imports: [
    AuthModule.forRoot({
      jwksUri: 'https://example.com/.well-known/jwks.json',
      clientId: 'client_id',
      issuerUri: 'https://example.com/',
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
})
export class AppModule {}
```

or set options with `ConfigService`

```typescript
@Module({
  imports: [
    AuthModule.forRootAsync({
      useFactory: (configService: ConfigService) => {
        return {
          jwksUri: configService.get('JWKS_URI'),
          clientId: configService.get('CLIENT_ID'),
          issuerUri: configService.get('ISSUER_URI'),
        };
      },
      imports: [ConfigModule],
      inject: [ConfigService],
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
  ],
})
export class AppModule {}
```

### Get decoded JWT payload

`AuthGuard` adds entire JWT payload to metadata. +
You can safely get JWT payload by using `isMetadataWithClaim` (Type Guard).

```typescript
if (isMetadataWithClaim(metadata)) {
  const { claim } = metadata;
}
```
