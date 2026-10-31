# Community OIDC pilot

Baseline: `twenty/v2.54.0`, commit `c75ef7bfd0589219bd22e8f134df458af0af3445`.
This fork adds an independent, optional OIDC login at `/auth/community-oidc`.
It uses the existing `openid-client` dependency and the ordinary Twenty login-token
redemption flow. The upstream frontend remains unchanged; use the dedicated login
URL or an Authentik application tile. There is no automatic signup or role syncing.

## License boundary

The existing OIDC/SAML strategies, guards and SSO controller are marked
`@license Enterprise`. They are neither changed, copied into the new adapter nor
unlocked. This patch only adds its own AGPL-3.0-only implementation and changes two
unmarked AGPL files: `auth/auth.module.ts` (register the new controller) and
`workspace/types/workspace.type.ts` (distinct `community-oidc` audit identity).
It uses the unmarked `LoginTokenService`, existing user/workspace repositories and
ordinary login redemption/MFA checks. Existing enterprise code and licensing guards
remain as shipped upstream. The repository's mixed-license LICENSE still applies.

## Configuration

| Variable | Meaning |
| --- | --- |
| `COMMUNITY_OIDC_ENABLED` | `true`; disabled by default |
| `COMMUNITY_OIDC_ISSUER` | Exact HTTPS discovery issuer, including trailing slash |
| `COMMUNITY_OIDC_CLIENT_ID` | Confidential client ID |
| `COMMUNITY_OIDC_SECRET_FILE` | Read-only mounted client-secret file |
| `COMMUNITY_OIDC_REQUIRED_GROUP` | Required signed ID-token group |
| `COMMUNITY_OIDC_LINKS_FILE` | Read-only mounted explicit identity map |
| `SERVER_URL` | Canonical HTTPS Twenty origin |
| `REDIS_URL` | Existing private Redis, used for five-minute login transactions |

Configure Authentik with authorization-code flow, PKCE S256, RS256 signing,
`openid profile email`, `user_uuid` subject mode, and profile claims including
`groups`. Bind the Authentik application to the same allowed group. The strict
callback is `<SERVER_URL>/auth/community-oidc/callback` (no trailing slash).

An administrator creates this map using the existing immutable UUIDs:

```json
[
  {
    "issuer": "https://auth.example/application/o/twenty/",
    "subject": "authentik-user-uuid",
    "userId": "existing-twenty-user-uuid",
    "workspaceId": "existing-twenty-workspace-uuid"
  }
]
```

Each issuer/subject has exactly one mapping in this initial pilot. Ambiguity fails
closed. Matching email alone cannot link an account. The user must be enabled,
not deleted, and already a member of an active, non-suspended workspace. No user,
membership, role, company or contact is created or modified by the OIDC adapter.
Company UUIDs (`customer_id`) therefore remain outside this login change.

Transactions use a Secure/HttpOnly/SameSite=Lax browser cookie and an atomic Redis
GETDEL with a five-minute TTL. State, nonce and PKCE verifier stay server-side.
`openid-client` checks signatures, issuer, audience, expiry, nonce and authorized
party; the adapter additionally checks group, subject and future issued-at claims.
No IdP tokens are persisted. Twenty's native single-use login token finishes the
existing login flow and preserves its MFA and workspace checks. Errors are opaque,
responses are not cached, and callback responses suppress referrers.

## Session behavior

Normal Twenty session, refresh and logout behavior applies. IdP group removal
blocks subsequent OIDC logins; it does not immediately revoke existing Twenty
sessions. No global/front-channel/back-channel logout is implemented. The separate
Demo 1 pilot configures a one-hour absolute session lifetime. Production password,
API and agent logins are unaffected; retain a recovery login before any production
migration. This initial adapter is not exposed in Twenty's enterprise SSO settings.

## Build and verification

```sh
docker build -f packages/twenty-docker/community-oidc/Dockerfile \
  --build-arg REVISION=$(git rev-parse HEAD) -t elmar-twenty-sso:development .
docker compose -f packages/twenty-docker/community-oidc/test-compose.yaml run --rm tests
```

The build uses the exact deployed upstream image digest and its existing TypeScript
compiler/dependencies. It compiles the four changed/new TypeScript files and performs
a focused strict typecheck of the OIDC protocol helper. No new runtime packages are
installed. The compiler refuses to process an Enterprise-marked file. A full Nx
monorepo build/typecheck is not part of this small pilot build.

The 40 focused tests use Node's built-in runner and the actual bundled openid-client,
a local mock token/JWKS server and real RSA signatures. The test container has no
external network. Cases cover valid exchange, bad signatures/claims, missing ID
tokens, state/nonce/PKCE, replay/expiry, explicit links, disabled/deleted users,
missing/deleted memberships and inactive/suspended workspaces. Controller wiring,
native token redemption and persistent identity are verified in the browser pilot.

Deployment and synthetic onboarding are managed separately in
`ElmarAI/BusinessSystem/prototyp1/twenty-sso-pilot`. Pilot secrets, identity maps and
customer material never belong in this fork. Corresponding source and build files
are available at https://github.com/ElmarAI/twenty/tree/elmar/authentik-oidc.
Pin the source revision and image, and repeat these tests plus the browser pilot
when taking upstream updates. Registry/CI publication is not configured yet.

The adapter scopes discovery, token and JWKS HTTP options to its own issuer/client,
without changing global hooks. The issuer is administrator-configured and may be
on a private network. The callback reads its cookie directly from the raw header;
Twenty does not install cookie-parser middleware. Duplicate cookies fail closed.
