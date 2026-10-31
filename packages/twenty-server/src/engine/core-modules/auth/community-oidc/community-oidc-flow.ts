// SPDX-License-Identifier: AGPL-3.0-only
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import {
  Issuer,
  generators,
  custom,
  type Client,
  type CallbackParamsType,
} from 'openid-client';
import Redis from 'ioredis';

export type IdentityLink = {
  issuer: string;
  subject: string;
  userId: string;
  workspaceId: string;
};
export type LoginTransaction = {
  state: string;
  nonce: string;
  verifier: string;
  started: number;
};
export const TRANSACTION_COOKIE = '__Secure-twenty-community-oidc';
export const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'lax' as const,
  path: '/auth/community-oidc',
};

export const requireHttpsUrl = (value: string): string => {
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error('Invalid OIDC URL');
  }
  return value;
};

export const findIdentityLink = (
  links: IdentityLink[],
  issuer: string,
  subject: string,
): IdentityLink => {
  const matches = links.filter(
    (link) => link.issuer === issuer && link.subject === subject,
  );
  const uuid =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (
    matches.length !== 1 ||
    !uuid.test(matches[0].userId) ||
    !uuid.test(matches[0].workspaceId)
  ) {
    throw new Error('Identity is not explicitly linked');
  }
  return matches[0];
};

export const validateGroupAndSubject = (
  claims: Record<string, unknown>,
  group: string,
): string => {
  if (
    !group ||
    !Array.isArray(claims.groups) ||
    !claims.groups.includes(group) ||
    typeof claims.sub !== 'string' ||
    !claims.sub ||
    claims.sub.length > 255 ||
    typeof claims.iat !== 'number' ||
    !Number.isFinite(claims.iat) ||
    claims.iat > Date.now() / 1000 + 30
  ) {
    throw new Error('Identity denied');
  }
  return claims.sub;
};

export const validateLinkedAccount = (
  user: { disabled: boolean; deletedAt?: Date | null } | null,
  membership: { deletedAt?: Date | null } | null,
  workspace: {
    activationStatus: string;
    suspendedAt?: Date | null;
    deletedAt?: Date | null;
  } | null,
): void => {
  if (
    !user ||
    user.disabled ||
    user.deletedAt ||
    !membership ||
    membership.deletedAt ||
    !workspace ||
    workspace.activationStatus !== 'ACTIVE' ||
    workspace.suspendedAt ||
    workspace.deletedAt
  ) {
    throw new Error('Account or workspace denied');
  }
};

// This administrator-configured issuer can live on a private network.
// Keep HTTP settings scoped to this adapter, including discovery and JWKS.
export class CommunityOidcIssuer extends Issuer {
  static [custom.http_options] = () => ({
    timeout: 10000,
    followRedirect: false,
  });
}

export class CommunityOidcFlow {
  private client?: Client;
  private cache?: Redis;

  constructor(private readonly environment: NodeJS.ProcessEnv = process.env) {}

  configuration() {
    if (this.environment.COMMUNITY_OIDC_ENABLED !== 'true')
      throw new Error('OIDC disabled');
    const issuer = requireHttpsUrl(
      this.environment.COMMUNITY_OIDC_ISSUER ?? '',
    );
    const server = requireHttpsUrl(this.environment.SERVER_URL ?? '').replace(
      /\/$/,
      '',
    );
    const clientId = this.environment.COMMUNITY_OIDC_CLIENT_ID;
    const group = this.environment.COMMUNITY_OIDC_REQUIRED_GROUP;
    const secret = readFileSync(
      this.environment.COMMUNITY_OIDC_SECRET_FILE ?? '',
      'utf8',
    ).trim();
    if (!clientId || !group || !secret)
      throw new Error('Incomplete OIDC configuration');
    return {
      issuer,
      server,
      clientId,
      group,
      secret,
      callback: `${server}/auth/community-oidc/callback`,
    };
  }

  async getClient(): Promise<Client> {
    const config = this.configuration();
    if (!this.client) {
      const issuer = await CommunityOidcIssuer.discover(config.issuer);
      issuer[custom.http_options] = CommunityOidcIssuer[custom.http_options];
      const methods = issuer.metadata.code_challenge_methods_supported;
      if (
        issuer.issuer !== config.issuer ||
        !Array.isArray(methods) ||
        !methods.includes('S256')
      ) {
        throw new Error('Issuer or PKCE mismatch');
      }
      for (const endpoint of [
        issuer.authorization_endpoint,
        issuer.token_endpoint,
        issuer.jwks_uri,
      ]) {
        if (typeof endpoint !== 'string')
          throw new Error('Missing OIDC endpoint');
        requireHttpsUrl(endpoint);
      }
      this.client = new issuer.Client({
        client_id: config.clientId,
        client_secret: config.secret,
        redirect_uris: [config.callback],
        response_types: ['code'],
        id_token_signed_response_alg: 'RS256',
        token_endpoint_auth_method: 'client_secret_basic',
      });
      this.client[custom.http_options] = () => ({
        timeout: 10000,
        followRedirect: false,
      });
    }
    return this.client;
  }

  private getCache(): Redis {
    if (!this.cache) {
      this.cache = new Redis(this.environment.REDIS_URL ?? '', {
        maxRetriesPerRequest: 1,
      });
      this.cache.on('error', () => undefined);
    }
    return this.cache;
  }

  private transactionKey(cookie: string): string {
    if (!/^[A-Za-z0-9_-]{43}$/.test(cookie))
      throw new Error('Invalid transaction');
    return `community-oidc:${createHash('sha256').update(cookie).digest('hex')}`;
  }

  async initiate(): Promise<{ cookie: string; url: string }> {
    const client = await this.getClient();
    const transaction: LoginTransaction = {
      state: generators.state(),
      nonce: generators.nonce(),
      verifier: generators.codeVerifier(),
      started: Date.now(),
    };
    const cookie = randomBytes(32).toString('base64url');
    const stored = await this.getCache().set(
      this.transactionKey(cookie),
      JSON.stringify(transaction),
      'EX',
      300,
      'NX',
    );
    if (stored !== 'OK') throw new Error('Transaction not stored');
    return {
      cookie,
      url: client.authorizationUrl({
        scope: 'openid profile email',
        state: transaction.state,
        nonce: transaction.nonce,
        code_challenge: generators.codeChallenge(transaction.verifier),
        code_challenge_method: 'S256',
        response_type: 'code',
      }),
    };
  }

  async consume(cookie: string): Promise<LoginTransaction> {
    const serialized = await this.getCache().getdel(
      this.transactionKey(cookie),
    );
    if (!serialized) throw new Error('Missing or replayed transaction');
    const transaction: LoginTransaction = JSON.parse(serialized);
    if (
      Date.now() - transaction.started > 300000 ||
      transaction.started > Date.now()
    ) {
      throw new Error('Expired transaction');
    }
    return transaction;
  }

  async authenticate(
    cookie: string,
    parameters: CallbackParamsType,
  ): Promise<IdentityLink> {
    const transaction = await this.consume(cookie);
    if (
      !parameters.code ||
      parameters.error ||
      parameters.id_token ||
      parameters.access_token
    ) {
      throw new Error('Authorization code required');
    }
    const config = this.configuration();
    const client = await this.getClient();
    const tokens = await client.callback(config.callback, parameters, {
      state: transaction.state,
      nonce: transaction.nonce,
      code_verifier: transaction.verifier,
      response_type: 'code',
    });
    if (!tokens.id_token) throw new Error('ID token required');
    const subject = validateGroupAndSubject(tokens.claims(), config.group);
    const links = JSON.parse(
      readFileSync(this.environment.COMMUNITY_OIDC_LINKS_FILE ?? '', 'utf8'),
    );
    if (!Array.isArray(links)) throw new Error('Invalid identity map');
    return findIdentityLink(links, config.issuer, subject);
  }
}
