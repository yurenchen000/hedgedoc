/*
 * SPDX-FileCopyrightText: 2021 The HedgeDoc developers (see AUTHORS file)
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */
import { BadRequestException, ExecutionContext, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import Strategy from 'passport-ldapauth';

import authConfiguration, { AuthConfig } from '../../config/auth.config';
import { UsersService } from '../../users/users.service';
import { User } from '../../users/user.entity';

@Injectable()
export class LdapAuthGuard extends AuthGuard('ldap') {
  canActivate(context: ExecutionContext): boolean {
    context.switchToHttp().getRequest();

    return true;
  }
}

@Injectable()
export class LdapStrategy extends PassportStrategy(Strategy, 'ldap') {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  constructor(
    private userService: UsersService,
    @Inject(authConfiguration.KEY)
    private authConfig: AuthConfig,
    private identifier: string,
  ) {
    const ldapConfig = authConfig.ldap.find(
      (ldapEntry) => ldapEntry.identifier === identifier,
    );
    if (ldapConfig === undefined) {
      throw new NotFoundException();
    }
    super(
      {
        server: {
          url: ldapConfig.url,
          bindDN: ldapConfig.bindDn,
          bindCredentials: ldapConfig.bindCredentials,
          searchBase: ldapConfig.searchBase,
          searchFilter: ldapConfig.searchFilter,
          searchAttributes: ldapConfig.searchAttributes,
          tlsOptions: {
            ca: ldapConfig.tlsCa,
          },
        },
        usernameField: ldapConfig.usernameField,
      },
      async (req: Request, user: User, done) => {
      req.user = user;
      return done(null, user);
    });
  }
}
