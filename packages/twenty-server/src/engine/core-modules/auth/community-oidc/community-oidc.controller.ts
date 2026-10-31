// SPDX-License-Identifier: AGPL-3.0-only
import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Request, Response } from 'express';
import { Repository } from 'typeorm';
import { LoginTokenService } from 'src/engine/core-modules/auth/token/services/login-token.service';
import { UserEntity } from 'src/engine/core-modules/user/user.entity';
import { UserWorkspaceEntity } from 'src/engine/core-modules/user-workspace/user-workspace.entity';
import { WorkspaceEntity } from 'src/engine/core-modules/workspace/workspace.entity';
import { AuthProviderEnum } from 'src/engine/core-modules/workspace/types/workspace.type';
import { NoPermissionGuard } from 'src/engine/guards/no-permission.guard';
import { PublicEndpointGuard } from 'src/engine/guards/public-endpoint.guard';
import {
  CommunityOidcFlow,
  TRANSACTION_COOKIE,
  COOKIE_OPTIONS,
  readTransactionCookie,
  validateLinkedAccount,
} from './community-oidc-flow';

@Controller('auth/community-oidc')
@UseGuards(PublicEndpointGuard, NoPermissionGuard)
export class CommunityOidcController {
  private readonly flow = new CommunityOidcFlow();

  constructor(
    private readonly loginTokens: LoginTokenService,
    @InjectRepository(UserEntity)
    private readonly users: Repository<UserEntity>,
    @InjectRepository(UserWorkspaceEntity)
    private readonly memberships: Repository<UserWorkspaceEntity>,
    @InjectRepository(WorkspaceEntity)
    private readonly workspaces: Repository<WorkspaceEntity>,
  ) {}

  @Get()
  async initiate(@Res() response: Response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    try {
      const { cookie, url } = await this.flow.initiate();
      response.cookie(TRANSACTION_COOKIE, cookie, {
        ...COOKIE_OPTIONS,
        maxAge: 300000,
      });
      return response.redirect(url);
    } catch {
      return response
        .status(403)
        .send('SSO sign-in failed. Contact your administrator.');
    }
  }

  @Get('callback')
  async callback(@Req() request: Request, @Res() response: Response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.clearCookie(TRANSACTION_COOKIE, COOKIE_OPTIONS);
    try {
      const client = await this.flow.getClient();
      const link = await this.flow.authenticate(
        readTransactionCookie(request.headers.cookie),
        client.callbackParams(request),
      );
      const [user, membership, workspace] = await Promise.all([
        this.users.findOneBy({ id: link.userId }),
        this.memberships.findOneBy({
          userId: link.userId,
          workspaceId: link.workspaceId,
        }),
        this.workspaces.findOneBy({ id: link.workspaceId }),
      ]);
      validateLinkedAccount(user, membership, workspace);
      if (!user) throw new Error('Missing user');
      const loginToken = await this.loginTokens.generateLoginToken(
        user.email,
        link.workspaceId,
        AuthProviderEnum.CommunityOidc,
      );
      const redirect = new URL('/verify', this.flow.configuration().server);
      redirect.searchParams.set('loginToken', loginToken.token);
      return response.redirect(redirect.toString());
    } catch {
      return response
        .status(403)
        .send('SSO sign-in failed. Contact your administrator.');
    }
  }
}
