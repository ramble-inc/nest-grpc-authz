import { DynamicModule, HttpModule, Module, Provider } from '@nestjs/common';
import {
  AUTH_OPTIONS,
  AuthModuleAsyncOptions,
  AuthModuleOptions,
  AuthModuleOptionsFactory,
} from './auth.interface';
import { AuthService } from './auth.service';

@Module({
  imports: [HttpModule],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {
  static forRoot(options: AuthModuleOptions): DynamicModule {
    return {
      module: AuthModule,
      imports: [HttpModule],
      providers: [
        AuthService,
        {
          provide: AUTH_OPTIONS,
          useValue: options,
        },
      ],
      exports: [AuthService],
    };
  }

  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    return {
      module: AuthModule,
      imports: [HttpModule, ...options.imports],
      providers: [AuthService, ...AuthModule.createAsyncProviders(options)],
      exports: [AuthService],
    };
  }

  private static createAsyncProviders(
    options: AuthModuleAsyncOptions,
  ): Provider[] {
    if (options.useFactory) {
      return [AuthModule.createAsyncOptionsProvider(options)];
    }
    return [
      AuthModule.createAsyncOptionsProvider(options),
      {
        provide: options.useClass,
        useClass: options.useClass,
      },
    ];
  }

  private static createAsyncOptionsProvider(
    options: AuthModuleAsyncOptions,
  ): Provider {
    if (options.useFactory) {
      return {
        provide: AUTH_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || [],
      };
    }
    return {
      provide: AUTH_OPTIONS,
      useFactory: async (optionsFactory: AuthModuleOptionsFactory) => {
        return optionsFactory.createAuthModuleOptions();
      },
      inject: [options.useClass],
    };
  }
}
