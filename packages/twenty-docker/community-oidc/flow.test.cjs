// SPDX-License-Identifier: AGPL-3.0-only
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Issuer, generators } = require('/app/node_modules/openid-client');
const jwt = require('/app/node_modules/jsonwebtoken');
const {
  CommunityOidcFlow,
  requireHttpsUrl,
  findIdentityLink,
  validateGroupAndSubject,
  validateLinkedAccount,
} = require('/app/packages/twenty-server/dist/engine/core-modules/auth/community-oidc/community-oidc-flow');
const issuerUrl = 'https://issuer.example';
const callback = 'https://crm.example/auth/community-oidc/callback';
const userId = '10000000-0000-4000-8000-000000000001';
const workspaceId = '20000000-0000-4000-8000-000000000002';
const link = {
  issuer: issuerUrl,
  subject: 'stable-subject',
  userId,
  workspaceId,
};
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const alternateKey = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
}).privateKey;
let server, issuer, tempDirectory;
let overrides = {},
  signingKey = privateKey,
  omitIdToken = false,
  tokenRequests = 0;

before(async () => {
  tempDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'twenty-oidc-test-'));
  fs.writeFileSync(path.join(tempDirectory, 'secret'), 'test-secret');
  fs.writeFileSync(
    path.join(tempDirectory, 'links.json'),
    JSON.stringify([link]),
  );
  server = http.createServer((request, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/jwks') {
      return response.end(
        JSON.stringify({
          keys: [
            {
              ...publicKey.export({ format: 'jwk' }),
              kid: 'test',
              alg: 'RS256',
              use: 'sig',
            },
          ],
        }),
      );
    }
    if (request.url !== '/token') {
      response.statusCode = 404;
      return response.end('{}');
    }
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
    });
    request.on('end', () => {
      tokenRequests++;
      const parameters = new URLSearchParams(body);
      if (
        parameters.get('code_verifier') !== 'v'.repeat(43) ||
        parameters.get('code') !== 'code'
      ) {
        response.statusCode = 400;
        return response.end(JSON.stringify({ error: 'invalid_grant' }));
      }
      const claims = {
        iss: issuerUrl,
        aud: 'test-client',
        sub: link.subject,
        nonce: 'nonce',
        groups: ['crm-users'],
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
        ...overrides,
      };
      const tokens = {
        access_token: 'opaque',
        token_type: 'Bearer',
        expires_in: 60,
      };
      if (!omitIdToken)
        tokens.id_token = jwt.sign(claims, signingKey, {
          algorithm: 'RS256',
          keyid: 'test',
        });
      response.end(JSON.stringify(tokens));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  issuer = new Issuer({
    issuer: issuerUrl,
    authorization_endpoint: issuerUrl + '/authorize',
    token_endpoint: base + '/token',
    jwks_uri: base + '/jwks',
    code_challenge_methods_supported: ['S256'],
  });
});
after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(tempDirectory, { recursive: true });
});

function fixture({ links = [link], transaction = {}, environment = {} } = {}) {
  overrides = {};
  signingKey = privateKey;
  omitIdToken = false;
  fs.writeFileSync(
    path.join(tempDirectory, 'links.json'),
    JSON.stringify(links),
  );
  const flow = new CommunityOidcFlow({
    COMMUNITY_OIDC_ENABLED: 'true',
    COMMUNITY_OIDC_ISSUER: issuerUrl,
    SERVER_URL: 'https://crm.example',
    COMMUNITY_OIDC_CLIENT_ID: 'test-client',
    COMMUNITY_OIDC_REQUIRED_GROUP: 'crm-users',
    COMMUNITY_OIDC_SECRET_FILE: path.join(tempDirectory, 'secret'),
    COMMUNITY_OIDC_LINKS_FILE: path.join(tempDirectory, 'links.json'),
    ...environment,
  });
  flow.client = new issuer.Client({
    client_id: 'test-client',
    client_secret: 'test-secret',
    redirect_uris: [callback],
    response_types: ['code'],
    id_token_signed_response_alg: 'RS256',
  });
  const cookie = crypto.randomBytes(32).toString('base64url');
  const values = new Map([
    [
      flow.transactionKey(cookie),
      JSON.stringify({
        state: 'state',
        nonce: 'nonce',
        verifier: 'v'.repeat(43),
        started: Date.now(),
        ...transaction,
      }),
    ],
  ]);
  flow.cache = {
    getdel: async (key) => {
      const value = values.get(key);
      values.delete(key);
      return value;
    },
    set: async (key, value, expiry, seconds, condition) => {
      assert.equal(expiry, 'EX');
      assert.equal(seconds, 300);
      assert.equal(condition, 'NX');
      values.set(key, value);
      return 'OK';
    },
  };
  return { flow, cookie, values };
}
const params = { code: 'code', state: 'state' };

test('real code exchange, RSA signature, nonce, PKCE and explicit linking', async () => {
  const { flow, cookie } = fixture();
  assert.deepEqual(await flow.authenticate(cookie, params), link);
  await assert.rejects(flow.authenticate(cookie, params));
});
for (const [name, change] of Object.entries({
  issuer: { iss: 'https://evil.example' },
  audience: { aud: 'wrong' },
  nonce: { nonce: 'wrong' },
  expiry: { exp: 1 },
  futureIat: { iat: Math.floor(Date.now() / 1000) + 3600 },
  azp: { aud: ['test-client', 'other'], azp: 'other' },
  group: { groups: [] },
  groupType: { groups: 'crm-users' },
  subject: { sub: '' },
})) {
  test(`reject invalid ${name}`, async () => {
    const { flow, cookie } = fixture();
    overrides = change;
    await assert.rejects(flow.authenticate(cookie, params));
  });
}
test('reject forged signature', async () => {
  const { flow, cookie } = fixture();
  signingKey = alternateKey;
  await assert.rejects(flow.authenticate(cookie, params));
});
test('reject absent ID token', async () => {
  const { flow, cookie } = fixture();
  omitIdToken = true;
  await assert.rejects(flow.authenticate(cookie, params));
});
for (const [name, altered] of Object.entries({
  state: { ...params, state: 'wrong' },
  missingState: { code: 'code' },
  missingCode: { state: 'state' },
  denied: { ...params, error: 'access_denied' },
  implicit: { ...params, id_token: 'injected' },
})) {
  test(`reject ${name} without exchanging the code`, async () => {
    const { flow, cookie } = fixture();
    const before = tokenRequests;
    await assert.rejects(flow.authenticate(cookie, altered));
    assert.equal(tokenRequests, before);
  });
}
test('reject missing browser transaction', async () => {
  const { flow } = fixture();
  const before = tokenRequests;
  await assert.rejects(flow.authenticate('', params));
  assert.equal(tokenRequests, before);
});
test('reject expired transaction', async () => {
  const { flow, cookie } = fixture({
    transaction: { started: Date.now() - 300001 },
  });
  await assert.rejects(flow.authenticate(cookie, params));
});
test('reject incorrect PKCE verifier', async () => {
  const { flow, cookie } = fixture({ transaction: { verifier: 'wrong' } });
  await assert.rejects(flow.authenticate(cookie, params));
});
test('reject unlinked subject even with matching email', async () => {
  const { flow, cookie } = fixture({ links: [] });
  overrides = { email: 'alex@example.org' };
  await assert.rejects(flow.authenticate(cookie, params));
});
test('initiate stores state/nonce/verifier only server side', async () => {
  const { flow, values } = fixture();
  const result = await flow.initiate();
  const transaction = JSON.parse(
    values.get(flow.transactionKey(result.cookie)),
  );
  const url = new URL(result.url);
  assert.equal(url.searchParams.get('state'), transaction.state);
  assert.equal(url.searchParams.get('nonce'), transaction.nonce);
  assert.equal(
    url.searchParams.get('code_challenge'),
    generators.codeChallenge(transaction.verifier),
  );
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(!result.cookie.includes(transaction.verifier));
});
test('disabled by default', () => {
  assert.throws(() => new CommunityOidcFlow({}).configuration());
});
for (const value of [
  'http://issuer.example',
  'https://user:password@issuer.example',
  'https://issuer.example?q=1',
  'https://issuer.example/#x',
]) {
  test(`reject unsafe URL ${value.split('@').pop()}`, () =>
    assert.throws(() => requireHttpsUrl(value)));
}
test('identity mapping is unique and issuer scoped', () => {
  assert.throws(() => findIdentityLink([link, link], issuerUrl, link.subject));
  assert.throws(() =>
    findIdentityLink([link], 'https://other.example', link.subject),
  );
  assert.throws(() =>
    findIdentityLink([{ ...link, userId: 'invalid' }], issuerUrl, link.subject),
  );
});
for (const [name, user, member, workspace] of [
  ['missing user', null, {}, { activationStatus: 'ACTIVE' }],
  ['disabled user', { disabled: true }, {}, { activationStatus: 'ACTIVE' }],
  [
    'deleted user',
    { disabled: false, deletedAt: new Date() },
    {},
    { activationStatus: 'ACTIVE' },
  ],
  [
    'missing membership',
    { disabled: false },
    null,
    { activationStatus: 'ACTIVE' },
  ],
  [
    'deleted membership',
    { disabled: false },
    { deletedAt: new Date() },
    { activationStatus: 'ACTIVE' },
  ],
  [
    'inactive workspace',
    { disabled: false },
    {},
    { activationStatus: 'INACTIVE' },
  ],
  [
    'suspended workspace',
    { disabled: false },
    {},
    { activationStatus: 'ACTIVE', suspendedAt: new Date() },
  ],
]) {
  test(`reject ${name}`, () =>
    assert.throws(() => validateLinkedAccount(user, member, workspace)));
}
test('existing active membership accepted without role changes', () => {
  const user = { disabled: false },
    membership = { role: 'member' },
    workspace = { activationStatus: 'ACTIVE' };
  validateLinkedAccount(user, membership, workspace);
  assert.equal(membership.role, 'member');
});
