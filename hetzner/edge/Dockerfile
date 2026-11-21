# Caddy with the two modules this edge needs compiled in. Neither ships in the
# official binary, and Caddy has no runtime plugin loading, so a custom build is
# the only way to have either at all.
#
# Every version below is pinned, including the base images by digest: this image
# terminates TLS for every hostname branchLeft serves, and `caddy:2` moving under
# a rebuild would change that with no diff to read.

ARG CADDY_VERSION=2.11.9

FROM caddy:${CADDY_VERSION}-builder-alpine@sha256:d26fbc8a56ed8c3c1534f5573162d148ad3ed41732665da8526eb181fac0b728 AS builder

ARG CADDY_VERSION

# `caddy-ratelimit` is pinned to a commit rather than a tag on purpose. Its only
# tag, v0.1.0, predates both the removal of the repository's work-in-progress
# notice and the metrics work; the tag is older than the module's own stability
# claim, so it is the wrong thing to depend on.
#
# The Caddy version is named, not left to xcaddy's default of the latest release,
# so the binary is the version the base image tag and the ARG above both say.
# The --replace lines lift three transitive modules past the versions Caddy and
# the bouncer require, to the first releases that fix a published Go advisory
# (klauspost/compress GO-2026-6865, golang.org/x/net GO-2026-6860, and
# golang.org/x/crypto GO-2026-5932, whose fix has no tagged release yet, so it is
# pinned to the commit).
RUN xcaddy build v${CADDY_VERSION} \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.15.0 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v0.15.0 \
    --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db \
    --replace github.com/klauspost/compress=github.com/klauspost/compress@v1.20.2 \
    --replace golang.org/x/net=golang.org/x/net@v0.62.0 \
    --replace golang.org/x/crypto=golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2

FROM caddy:${CADDY_VERSION}-alpine@sha256:0bbb055bda6793c999bde78b1b5ce3e89f829fb031af2cf50056ea1246559fee

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# The base carries zlib 1.3.2-r1, which has CVE-2026-4738 (critical) with a fix in
# 1.4-r0 on the same Alpine release. Named, so a later base cannot move it silently.
RUN apk add --no-cache zlib=1.4-r0

# Ghost's front-end widgets, served by the edge at /bl-assets/ on every Ghost
# hostname (render.ts, `widgetAssets`). They are the pinned bundles in
# branchLeft/ghost-platform's widgets/dist/, fetched at that repository's commit
# and refused unless the bytes match the sha256 named here (`ADD --checksum` fails
# the build on a mismatch), so a build cannot pick up a changed file. To take a new
# pin: set WIDGET_SOURCE_COMMIT to the commit that holds it and replace the seven
# sums with `shasum -a 256 widgets/dist/*` from that commit. The seven files are
# the seven rows of that repository's widgets/pins.json; `widgetAssets.test.ts`
# fails when this list and the renderer's disagree.
ARG WIDGET_SOURCE_COMMIT=7863b17996a9e59bf74b157339487c2a2a71faf2
ARG WIDGET_BASE_URL=https://raw.githubusercontent.com/branchLeft/ghost-platform/${WIDGET_SOURCE_COMMIT}/widgets/dist
ADD --checksum=sha256:065472c5dc60c443cdb4332235a4cb9cd07f27f05f8b43cf69d2fc162d426754 --chmod=0644 ${WIDGET_BASE_URL}/admin-toolbar.min.js /srv/bl-assets/admin-toolbar.min.js
ADD --checksum=sha256:2f87745344dabf2c17a1fd8bf4761a5a0afcd11e7d1b1427b128d08cf2fd4dcf --chmod=0644 ${WIDGET_BASE_URL}/announcement-bar.min.js /srv/bl-assets/announcement-bar.min.js
ADD --checksum=sha256:af76fd41bd86e030ddff5b7bfa627da0ae1aa7f4534184fb92270c0209a33c34 --chmod=0644 ${WIDGET_BASE_URL}/comments-ui.min.js /srv/bl-assets/comments-ui.min.js
ADD --checksum=sha256:bf97c0a94eb564f0d3192d9ee1ea7534a0ed82c109c5111630076aed1e715583 --chmod=0644 ${WIDGET_BASE_URL}/portal.min.js /srv/bl-assets/portal.min.js
ADD --checksum=sha256:883b6f4b333a0654773eb40e4ef992f5a1550e4153b2fa99406ca50014d3903c --chmod=0644 ${WIDGET_BASE_URL}/signup-form.min.js /srv/bl-assets/signup-form.min.js
ADD --checksum=sha256:8351196b62e6c27858441427a27c8be4d08f0e2b3684c4c280de7bbfe2a2160a --chmod=0644 ${WIDGET_BASE_URL}/sodo-search.min.css /srv/bl-assets/sodo-search.min.css
ADD --checksum=sha256:5ff29320840e94565b12c15d90a4ab9c884a7e01783e17ac329f27dba3395688 --chmod=0644 ${WIDGET_BASE_URL}/sodo-search.min.js /srv/bl-assets/sodo-search.min.js

# Proves the two modules are actually registered rather than silently absent —
# an xcaddy build that resolved nothing still produces a working Caddy, and the
# first symptom would be a config full of unrecognised directives at deploy time.
RUN caddy list-modules | grep -qx 'http.handlers.rate_limit' \
    && caddy list-modules | grep -qx 'http.handlers.appsec' \
    && caddy list-modules | grep -qx 'http.handlers.crowdsec'
