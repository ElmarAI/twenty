FROM twentycrm/twenty:v2.54.0@sha256:e64479a4daa9211864eb45ffdf15ce7a44a3664850dab06213105027538fce1e
USER root
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/ElmarAI/twenty" \
      org.opencontainers.image.revision=$REVISION
COPY packages/twenty-server/src/engine/core-modules/auth/auth.module.ts /oidc-source/engine/core-modules/auth/auth.module.ts
COPY packages/twenty-server/src/engine/core-modules/auth/community-oidc /oidc-source/engine/core-modules/auth/community-oidc
COPY packages/twenty-server/src/engine/core-modules/workspace/types/workspace.type.ts /oidc-source/engine/core-modules/workspace/types/workspace.type.ts
COPY packages/twenty-docker/community-oidc/build.cjs /oidc-source/build.cjs
RUN node /oidc-source/build.cjs
USER 1000
